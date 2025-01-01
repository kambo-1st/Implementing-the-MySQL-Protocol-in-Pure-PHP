<?php

namespace OurMySQL;

use RuntimeException;
use ValueError;

use function socket_create;
use function socket_strerror;
use function socket_last_error;
use function socket_connect;
use function socket_read;
use function ord;
use function var_dump;
use function substr;
use function strlen;
use function max;
use function pack;
use function chr;
use function str_repeat;
use function implode;
use function unpack;
use function array_shift;
use function assert;
use function strpos;
use function hash;
use function socket_write;
use function openssl_public_encrypt;
use function ceil;
use function openssl_pkey_get_public;

use const AF_INET;
use const SOCK_STREAM;
use const SOL_TCP;
use const PHP_INT_SIZE;
use const OPENSSL_PKCS1_OAEP_PADDING;

class Client
{
    private $socket;
    public const CLIENT_PLUGIN_AUTH = 0x00080000;
    public const CLIENT_SECURE_CONNECTION = 0x00008000;

    public const CLIENT_LONG_FLAG = 0x00000004;
    public const CLIENT_CONNECT_WITH_DB = 0x00000008;
    public const CLIENT_COMPRESS = 0x00000020;
    public const CLIENT_LOCAL_INFILE = 0x00000080;
    public const CLIENT_PROTOCOL_41 = 0x00000200;
    public const CLIENT_SSL = 0x00000800;
    public const CLIENT_TRANSACTIONS = 0x00002000;
    public const CLIENT_MULTI_STATEMENTS = 0x00010000;
    public const CLIENT_MULTI_RESULTS = 0x00020000;
    public const CLIENT_PS_MULTI_RESULTS = 0x00040000;
    public const CLIENT_CONNECT_ATTRS = 0x00100000;
    public const CLIENT_SESSION_TRACK = 0x00800000;
    public const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000;
    public const CLIENT_DEPRECATE_EOF = 0x01000000;

    public const MAX_PACKET_LENGTH = 0x00ffffff;
    public const BIN_CHARSET = 255;
    //public const CLIENT_PLUGIN_AUTH = 0x00080000;

    private const LONG_DATA_TYPE = 0x03;

    private const COM_QUERY = 0x03;

    public const OK_PACKET = 0x00;
    public const AUTH_MORE_DATA = 0x01;
    public const LOCAL_INFILE_REQUEST = 0xfb;
    public const AUTH_SWITCH_PACKET = 0xfe;
    public const EOF_PACKET = 0xfe;
    public const ERR_PACKET = 0xff;

    private const PROTOCOL_VERSION = 0x0a;

    private const CACHING_SHA2_REUSE = 3;
    private const CACHING_SHA2_NEED_FULL_AUTH = 4;

    private const REQUEST_PUBLIC_KEY = "\x02";
    private const PUBLIC_KEY_RESPONSE = 0x2d;

    public function __construct(
        string $server,
        string $username,
        string $password,
        ?string $database = null,
        int $port = 3306
    ) {
        // Initialize socket connection
        $this->socket = $this->initializeSocket($server, $port);

        // Perform handshake with the server
        $handshakeData = $this->performHandshake();

        // Authenticate the client
        $this->authenticateClient($username, $password, $database, $handshakeData);
    }

    private function initializeSocket(string $server, int $port) {
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

        if (!$socket) {
            throw new RuntimeException('Failed to create socket: ' . socket_strerror(socket_last_error()));
        }

        if (!socket_connect($socket, $server, $port)) {
            throw new RuntimeException('Failed to connect to server: ' . socket_strerror(socket_last_error($socket)));
        }

        return $socket;
    }

    private function performHandshake(): array {
        [$seqId, $handshake] = $this->getPacket();

        $offset = 0;
        $protocol = $this->decodeUnsigned8($handshake, $offset);
        if ($protocol !== self::PROTOCOL_VERSION) {
            throw new RuntimeException('Invalid protocol version');
        }

        $version = $this->decodeNullTerminatedString($handshake, $offset);
        $connectionId = $this->decodeUnsigned32($handshake, $offset);

        $authPluginData = substr($handshake, $offset, 8);
        $offset += 8; // Skip scramble data
        $offset += 1; // Skip null byte

        $serverCapabilities = $this->decodeUnsigned16($handshake, $offset);
        $charset = $this->decodeUnsigned8($handshake, $offset);
        $statusFlags = $this->decodeUnsigned16($handshake, $offset);
        $serverCapabilities += $this->decodeUnsigned16($handshake, $offset) << 16;

        $authPluginDataLen = $serverCapabilities & self::CLIENT_PLUGIN_AUTH
            ? $this->decodeUnsigned8($handshake, $offset)
            : 0;

        $authPluginName = null;
        if ($serverCapabilities & self::CLIENT_SECURE_CONNECTION) {
            $offset += 10;

            $strlen = max(13, $authPluginDataLen - 8);
            $authPluginData .= substr($handshake, $offset, $strlen);
            $offset += $strlen;

            if ($serverCapabilities & self::CLIENT_PLUGIN_AUTH) {
                $authPluginName = $this->decodeNullTerminatedString($handshake, $offset);
            }
        }

        if ($authPluginName !== 'caching_sha2_password') {
            throw new RuntimeException('Only caching_sha2_password is supported');
        }

        return [
            'authPluginData' => $authPluginData,
            'serverCapabilities' => $serverCapabilities,
            'authPluginName' => $authPluginName
        ];
    }

    private function authenticateClient(string $username, string $password, ?string $database, array $handshakeData): void {
        $clientCapabilities = self::CLIENT_SESSION_TRACK
            | self::CLIENT_TRANSACTIONS
            | self::CLIENT_PROTOCOL_41
            | self::CLIENT_SECURE_CONNECTION
            | self::CLIENT_MULTI_RESULTS
            | self::CLIENT_PS_MULTI_RESULTS
            | self::CLIENT_MULTI_STATEMENTS
            | self::CLIENT_PLUGIN_AUTH
            | self::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;

        if ($database !== null) {
            $clientCapabilities |= self::CLIENT_CONNECT_WITH_DB;
        }

        $clientCapabilities &= $handshakeData['serverCapabilities'];

        $payload = [
            pack('V', $clientCapabilities),
            pack('V', self::MAX_PACKET_LENGTH),
            chr(self::BIN_CHARSET),
            str_repeat("\0", 23), // Reserved
            $username . "\0",
        ];

        $auth = $this->sha2Auth($password, $handshakeData['authPluginData']);

        if ($clientCapabilities & self::CLIENT_SECURE_CONNECTION) {
            $payload[] = chr(strlen($auth));
            $payload[] = $auth;
        } else {
            $payload[] = $auth . "\0";
        }

        if ($clientCapabilities & self::CLIENT_CONNECT_WITH_DB) {
            $payload[] = $database . "\0";
        }

        if ($clientCapabilities & self::CLIENT_PLUGIN_AUTH) {
            $payload[] = $handshakeData['authPluginName'] . "\0";
        }

        $seqId = 0;
        $this->sendPacket(implode($payload), $seqId);

        [$seqId, $packet] = $this->getPacket();
        $offset = 0;
        $protocol = $this->decodeUnsigned8($packet, $offset);

        if ($protocol === self::AUTH_MORE_DATA) {
            $result = $this->decodeUnsigned8($packet, $offset);
            if ($result !== self::CACHING_SHA2_REUSE) {
                if ($result === self::CACHING_SHA2_NEED_FULL_AUTH) {
                    $this->fullAuthentification($seqId, $password, $handshakeData['authPluginData']);
                } else {
                    throw new RuntimeException('Error during authentication');
                }
            }
        } else {
            throw new RuntimeException('Expecting AUTH_MORE_DATA packet');
        }

        [$seqId, $packet] = $this->getPacket();
        $offset = 0;
        $result = $this->decodeUnsigned8($packet, $offset);

        if ($result !== self::OK_PACKET) {
            $this->handleError($packet);
        }
    }

    private function handleError(string $packet): void {
        $offset     = 1;
        $errorCode  = self::decodeUnsigned16($packet, $offset);
        $errorState = substr($packet, $offset, 6);
        $offset    += 6;

        $errorMsg = substr($packet, $offset);

        throw new RuntimeException($errorMsg);
    }

    private function sha256Auth(string $pass, string $scramble, string $key): string {
        openssl_public_encrypt(
            "$pass\0" ^ str_repeat($scramble, (int) ceil(strlen($pass) / strlen($scramble))),
            $auth,
            openssl_pkey_get_public($key),
            OPENSSL_PKCS1_OAEP_PADDING,
        );

        return $auth;
    }

    public function query(string $query): array {
        $seqId = -1;
        $this->sendPacket(chr(self::COM_QUERY) . $query, $seqId);

        $packets = $this->getPackets();

        $columnCountRawPacket = array_shift($packets);
        [$seqId, $columnCountPacket] = $columnCountRawPacket;
        $offset = 0;
        $columnCount = self::readLengthEncodedInt($columnCountPacket, $offset);

        $columnsDefinition = [];
        for ($i = 0; $i < $columnCount; $i++) {
            $columnRawPacket = array_shift($packets);
            [$seqId, $columnPacket] = $columnRawPacket;
            $offset = 0;
            $column = self::getColumn($columnPacket, $offset);
            $columnsDefinition[] = $column;
        }

        $eofRawPacket = array_shift($packets);
        [$seqId, $eofPacket] = $eofRawPacket;

        if (ord($eofPacket) !== self::EOF_PACKET) {
            throw new RuntimeException('Invalid protocol - EOF expected');
        }

        $rows = [];
        while (true) {
            $rawRowPacket = array_shift($packets);
            [$seqId, $rowPacket] = $rawRowPacket;

            $offset = 0;
            $rowFields = [];

            if (ord($rowPacket) === self::EOF_PACKET) {
                break;
            }

            for ($i = 0; $offset < strlen($rowPacket); ++$i) {
                if (ord($rowPacket[$offset]) === 0xfb) {
                    $rowFields[] = null;
                    $offset += 1;
                } else {
                    $rowFields[$i] = $this->decodeValue($rowPacket, $columnsDefinition[$i], $offset);
                }
            }

            $rows[] = $rowFields;
        }

        return $rows;
    }

    private static function decodeUnsigned(string $bytes, int &$offset = 0): int {
        $int = self::decodeUnsigned8($bytes, $offset);
        if ($int < 0xfb) {
            return $int;
        }

        return match ($int) {
            0xfc => self::decodeUnsigned16($bytes, $offset),
            0xfd => self::decodeUnsigned24($bytes, $offset),
            0xfe => self::decodeUnsigned64($bytes, $offset),
            // If this happens connection is borked...
            default => throw new RuntimeException($int . ' is not in ranges [0x00, 0xfa] or [0xfc, 0xfe]'),
        };
    }

    private static function encodeInt32(int $int): string {
        return pack('V', $int);
    }

    private static function decodeString(string $bytes, int &$offset = 0): string {
        $length = self::decodeUnsigned($bytes, $offset);
        $offset += $length;
        return substr($bytes, $offset - $length, $length);
    }

    private static function decodeUnsigned64(string $bytes, int &$offset = 0): int {
        if (PHP_INT_SIZE <= 4) {
            throw new RuntimeException('64-bit integers are not supported by 32-bit builds of PHP');
        }

        $result = unpack('P', $bytes, $offset)[1];
        $offset += 8;

        if ($result < 0) {
            throw new RuntimeException('Expecting a non-negative integer');
        }

        return $result;
    }

    private static function decodeUnsigned24(string $bytes, int &$offset = 0): int {
        $result = unpack('V', substr($bytes, $offset, 3) . "\x00")[1];
        $offset += 3;
        return $result;
    }

    private static function decodeUnsigned8(string $bytes, int &$offset = 0): int {
        $result = ord($bytes[$offset++]);
        assert($result >= 0);
        return $result;
    }

    private static function decodeNullTerminatedString(string $bytes, int &$offset = 0): string {
        $length = strpos($bytes, "\0", $offset);
        if ($length === false) {
            throw new ValueError('Null not found in string');
        }

        $length -= $offset;
        $result = substr($bytes, $offset, $length);
        $offset += $length + 1;
        assert($offset >= 0);

        return $result;
    }

    private static function encodeInt8(int $int): string {
        return chr($int);
    }

    private static function encodeInt24(int $int): string {
        return substr(pack('V', $int), 0, 3);
    }

    private static function decodeUnsigned32(string $bytes, int &$offset = 0): int {
        $result = unpack('V', $bytes, $offset)[1];
        $offset += 4;

        if ($result < 0) {
            throw new RuntimeException('Expecting a non-negative integer');
        }

        return $result;
    }

    private static function decodeUnsigned16(string $bytes, int &$offset = 0): int {
        $offset += 2;
        return unpack('v', $bytes, $offset - 2)[1];
    }

    private static function readLengthEncodedString(&$response, &$offset): string {
        $length = self::readLengthEncodedInt($response, $offset);
        $string = substr($response, $offset, $length);
        $offset += $length;
        return $string;
    }

    private static function readLengthEncodedInt(&$response, &$offset): ?int {
        $firstByte = ord($response[$offset]);
        $offset++;

        if ($firstByte < 0xfb) {
            return $firstByte;
        } elseif ($firstByte == 0xfc) {
            $int = unpack('v', substr($response, $offset, 2))[1];
            $offset += 2;
            return $int;
        } elseif ($firstByte == 0xfd) {
            $int = unpack('V', substr($response, $offset, 3) . "\0")[1];
            $offset += 3;
            return $int;
        } elseif ($firstByte == 0xfe) {
            $int = unpack('P', substr($response, $offset, 8))[1];
            $offset += 8;
            return $int;
        }
        return null;
    }

    private static function getColumn($packet, &$offset): array {
        // https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_com_query_response_text_resultset_column_definition.html
        $column = [
            'catalog' => self::readLengthEncodedString($packet, $offset),
            'schema' => self::decodeString($packet, $offset),
            'table' => self::decodeString($packet, $offset),
            'originalTable' => self::decodeString($packet, $offset),
            'name' => self::decodeString($packet, $offset),
            'originalName' => self::decodeString($packet, $offset),
        ];

        // length of fixed length fields
        $fixLength = self::decodeUnsigned($packet, $offset);

        $column += [
            'charset' => self::decodeUnsigned16($packet, $offset),
            'length' => self::decodeUnsigned32($packet, $offset),
            'type' => self::decodeUnsigned8($packet, $offset),
            'flags' => self::decodeUnsigned16($packet, $offset),
            'decimals' => self::decodeUnsigned8($packet, $offset),
        ];

        $offset += $fixLength;

        if ($offset < strlen($packet)) {
            $column['defaults'] = self::decodeString($packet, $offset);
        }

        return $column;
    }

    private static function sha2Auth(string $pass, string $scramble): string {
        $digestStage1 = hash('sha256', $pass, true);
        $digestStage2 = hash('sha256', $digestStage1, true);
        $scrambleStage1 = hash('sha256', $digestStage2 . substr($scramble, 0, 20), true);
        return $digestStage1 ^ $scrambleStage1;
    }

    private function getPackets(): array {
        $greeting = socket_read($this->socket, 2048);
        if ($greeting === false || strlen($greeting) === 0) {
            throw new RuntimeException('Failed to read data from the socket.');
        }

        $packets = [];
        $offset = 0;

        while ($offset < strlen($greeting)) {
            $length = self::decodeUnsigned24($greeting, $offset);
            $seqId = self::decodeUnsigned8($greeting, $offset);

            if ($length > 0) {
                $packets[] = [$seqId, substr($greeting, $offset, $length)];
            }

            $offset += $length;
        }

        return $packets;
    }

    private function getPacket(): array {
        // Initialize buffer for packet reading
        $buffer = '';

        // Attempt to read the first 4 bytes for the header (packet length + sequence ID)
        // https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_packets.html
        $header = socket_read($this->socket, 4);
        if ($header === false || strlen($header) < 4) {
            throw new RuntimeException('Failed to read packet header from socket.');
        }

        // Decode packet length and sequence ID
        $offset = 0;
        $length = self::decodeUnsigned24($header, $offset);
        $seqId = self::decodeUnsigned8($header, $offset);

        // Read the full packet based on the decoded length
        while (strlen($buffer) < $length) {
            $chunk = socket_read($this->socket, $length - strlen($buffer));
            if ($chunk === false) {
                throw new RuntimeException('Failed to read complete packet from socket.');
            }
            $buffer .= $chunk;
        }

        return [$seqId, $buffer];
    }

    private function sendPacket(string $packet, &$seqId): void {
        $packet = self::encodeInt24(strlen($packet)). self::encodeInt8(++$seqId) . $packet;
        socket_write($this->socket, $packet);
    }

    private function decodeValue(string $bytes, array $column, int &$offset = 0): int|string {
        $length = self::decodeUnsigned($bytes, $offset);
        $offset += $length;
        $data = substr($bytes, $offset - $length, $length);

        if ($column['type'] === self::LONG_DATA_TYPE) {
            return (int) $data;
        }

        return $data;
    }

    private function fullAuthentification(mixed $seqId, ?string $password, string $authPluginData): array {
        $this->sendPacket(self::REQUEST_PUBLIC_KEY, $seqId);
        [$seqId, $packet] = $this->getPacket();

        $offset = 0;
        $protocol = self::decodeUnsigned8($packet, $offset);
        if ($protocol === self::AUTH_MORE_DATA) {
            $result = self::decodeUnsigned8($packet, $offset);
            if ($result === self::PUBLIC_KEY_RESPONSE) {
                $pubkey = substr($packet, 1);
                self::sendPacket(
                    $this->sha256Auth($password, $authPluginData, $pubkey),
                    $seqId
                );
            }
        }

        return [$seqId, $packet, $offset, $result];
    }
}
