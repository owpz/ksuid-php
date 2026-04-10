<?php

declare(strict_types=1);

namespace Owpz\Ksuid;

/**
 * K-Sortable Unique Identifier (KSUID) generator.
 *
 * A KSUID is a 20-byte identifier:
 *   - 4 bytes: big-endian uint32 timestamp (seconds since KSUID epoch 2014-05-13T16:53:20Z)
 *   - 16 bytes: cryptographically random payload
 *
 * Encoded as a 27-character base62 string, zero-padded for fixed width.
 * Lexicographically sortable by creation time.
 *
 * Cross-compatible with owpz/ksuid (TypeScript) and owpz/ksuid-rs (Rust).
 * Backward-compatible with segmentio/ksuid (Go).
 */
class Ksuid
{
    public const KSUID_EPOCH = 1400000000;
    public const PAYLOAD_BYTES = 16;
    public const TIMESTAMP_BYTES = 4;
    public const TOTAL_BYTES = 20;
    public const ENCODED_LENGTH = 27;

    private const BASE62_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    private string $raw;

    /**
     * @param string $raw 20-byte raw KSUID
     */
    private function __construct(string $raw)
    {
        if (strlen($raw) !== self::TOTAL_BYTES) {
            throw new \InvalidArgumentException(
                sprintf('KSUID raw bytes must be exactly %d bytes, got %d', self::TOTAL_BYTES, strlen($raw))
            );
        }
        $this->raw = $raw;
    }

    /**
     * Generate a new KSUID using the current time and cryptographically random bytes.
     */
    public static function generate(): self
    {
        $timestamp = time() - self::KSUID_EPOCH;
        if ($timestamp < 0 || $timestamp > 0xFFFFFFFF) {
            throw new \OverflowException('Current timestamp offset exceeds uint32 range for KSUID');
        }
        $payload = random_bytes(self::PAYLOAD_BYTES);

        $raw = pack('N', $timestamp) . $payload;

        return new self($raw);
    }

    /**
     * Create a KSUID from a specific Unix timestamp and payload.
     *
     * @param int $unixTimestamp Unix timestamp (will be adjusted by KSUID epoch)
     * @param string $payload 16 bytes of payload data
     */
    public static function fromParts(int $unixTimestamp, string $payload): self
    {
        if (strlen($payload) !== self::PAYLOAD_BYTES) {
            throw new \InvalidArgumentException(
                sprintf('Payload must be exactly %d bytes, got %d', self::PAYLOAD_BYTES, strlen($payload))
            );
        }

        $timestamp = $unixTimestamp - self::KSUID_EPOCH;
        if ($timestamp < 0) {
            throw new \InvalidArgumentException('Timestamp must be >= KSUID epoch (2014-05-13T16:53:20Z)');
        }
        if ($timestamp > 0xFFFFFFFF) {
            throw new \InvalidArgumentException('Timestamp offset exceeds uint32 max');
        }

        $raw = pack('N', $timestamp) . $payload;

        return new self($raw);
    }

    /**
     * Create a KSUID from a timestamp offset (seconds since KSUID epoch) and payload.
     * This matches the Go/TypeScript API where the timestamp parameter is the offset,
     * not the Unix timestamp.
     *
     * @param int $timestampOffset Seconds since KSUID epoch (2014-05-13T16:53:20Z)
     * @param string $payload 16 bytes of payload data
     */
    public static function fromTimestampOffset(int $timestampOffset, string $payload): self
    {
        if (strlen($payload) !== self::PAYLOAD_BYTES) {
            throw new \InvalidArgumentException(
                sprintf('Payload must be exactly %d bytes, got %d', self::PAYLOAD_BYTES, strlen($payload))
            );
        }

        if ($timestampOffset < 0 || $timestampOffset > 0xFFFFFFFF) {
            throw new \InvalidArgumentException('Timestamp offset must be between 0 and 4294967295');
        }

        $raw = pack('N', $timestampOffset) . $payload;

        return new self($raw);
    }

    /**
     * Parse a 27-character base62 KSUID string back into a Ksuid instance.
     */
    public static function parse(string $encoded): self
    {
        if (strlen($encoded) !== self::ENCODED_LENGTH) {
            throw new \InvalidArgumentException(
                sprintf('Encoded KSUID must be exactly %d characters, got %d', self::ENCODED_LENGTH, strlen($encoded))
            );
        }

        $raw = self::base62Decode($encoded);

        return new self($raw);
    }

    /**
     * Parse a KSUID string, returning null instead of throwing on invalid input.
     */
    public static function parseOrNull(string $encoded): ?self
    {
        try {
            return self::parse($encoded);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Create a Ksuid from raw 20-byte binary data.
     */
    public static function fromBytes(string $raw): self
    {
        return new self($raw);
    }

    /**
     * Create a Ksuid from raw bytes, returning null instead of throwing on invalid input.
     */
    public static function fromBytesOrNull(string $raw): ?self
    {
        try {
            return new self($raw);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Return the nil (zero) KSUID.
     */
    public static function nil(): self
    {
        return new self(str_repeat("\x00", self::TOTAL_BYTES));
    }

    /**
     * Check whether this KSUID is the nil (all-zero) value.
     */
    public function isNil(): bool
    {
        return $this->raw === str_repeat("\x00", self::TOTAL_BYTES);
    }

    /**
     * Encode this KSUID as a 27-character base62 string.
     */
    public function toString(): string
    {
        return self::base62Encode($this->raw);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Get the Unix timestamp embedded in this KSUID.
     */
    public function getTimestamp(): int
    {
        $unpacked = unpack('N', substr($this->raw, 0, self::TIMESTAMP_BYTES));
        return $unpacked[1] + self::KSUID_EPOCH;
    }

    /**
     * Get the timestamp offset (seconds since KSUID epoch).
     * This matches the Go/TypeScript `timestamp` property.
     */
    public function getTimestampOffset(): int
    {
        $unpacked = unpack('N', substr($this->raw, 0, self::TIMESTAMP_BYTES));
        return $unpacked[1];
    }

    /**
     * Get the creation time as a DateTimeImmutable.
     */
    public function getDate(): \DateTimeImmutable
    {
        return (new \DateTimeImmutable())->setTimestamp($this->getTimestamp());
    }

    /**
     * Get the 16-byte random payload.
     */
    public function getPayload(): string
    {
        return substr($this->raw, self::TIMESTAMP_BYTES);
    }

    /**
     * Get the raw 20-byte binary representation.
     */
    public function getBytes(): string
    {
        return $this->raw;
    }

    /**
     * Compare this KSUID with another.
     * Returns -1, 0, or 1 (like strcmp / spaceship operator).
     */
    public function compare(self $other): int
    {
        return $this->raw <=> $other->raw;
    }

    /**
     * Check equality with another KSUID.
     */
    public function equals(self $other): bool
    {
        return $this->raw === $other->raw;
    }

    /**
     * Return the next KSUID after this one (payload incremented by 1).
     * On payload overflow, the timestamp is incremented.
     */
    public function next(): self
    {
        $timestampOffset = $this->getTimestampOffset();
        $payload = $this->getPayload();

        // Increment the 16-byte payload as a big-endian unsigned integer
        $num = gmp_import($payload, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        $num = gmp_add($num, 1);

        // Check for overflow (payload exceeded 128-bit max)
        $maxPayload = gmp_sub(gmp_pow(2, 128), 1);
        if (gmp_cmp($num, $maxPayload) > 0) {
            // Payload overflowed — increment timestamp, reset payload to zero
            $timestampOffset++;
            $newPayload = str_repeat("\x00", self::PAYLOAD_BYTES);
        } else {
            $newPayload = str_pad(
                gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN),
                self::PAYLOAD_BYTES,
                "\x00",
                STR_PAD_LEFT
            );
        }

        $raw = pack('N', $timestampOffset & 0xFFFFFFFF) . $newPayload;

        return new self($raw);
    }

    /**
     * Return the previous KSUID before this one (payload decremented by 1).
     * On payload underflow, the timestamp is decremented.
     */
    public function prev(): self
    {
        $timestampOffset = $this->getTimestampOffset();
        $payload = $this->getPayload();

        $num = gmp_import($payload, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        $num = gmp_sub($num, 1);

        if (gmp_cmp($num, 0) < 0) {
            // Payload underflowed — decrement timestamp, set payload to max
            if ($timestampOffset === 0) {
                $timestampOffset = 0xFFFFFFFF;
            } else {
                $timestampOffset--;
            }
            $newPayload = str_repeat("\xFF", self::PAYLOAD_BYTES);
        } else {
            $exported = gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
            if ($exported === '' || $exported === false) {
                $exported = '';
            }
            $newPayload = str_pad($exported, self::PAYLOAD_BYTES, "\x00", STR_PAD_LEFT);
        }

        $raw = pack('N', $timestampOffset & 0xFFFFFFFF) . $newPayload;

        return new self($raw);
    }

    /**
     * Encode raw bytes as a zero-padded base62 string.
     */
    private static function base62Encode(string $data): string
    {
        $num = gmp_import($data, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        if (gmp_cmp($num, 0) === 0) {
            return str_repeat('0', self::ENCODED_LENGTH);
        }

        $base = gmp_init(62);
        $result = '';

        while (gmp_cmp($num, 0) > 0) {
            [$num, $remainder] = gmp_div_qr($num, $base);
            $result = self::BASE62_CHARS[gmp_intval($remainder)] . $result;
        }

        return str_pad($result, self::ENCODED_LENGTH, '0', STR_PAD_LEFT);
    }

    /**
     * Decode a base62 string back to raw bytes.
     */
    private static function base62Decode(string $encoded): string
    {
        $base = gmp_init(62);
        $num = gmp_init(0);

        for ($i = 0; $i < strlen($encoded); $i++) {
            $char = $encoded[$i];
            $value = strpos(self::BASE62_CHARS, $char);

            if ($value === false) {
                throw new \InvalidArgumentException(
                    sprintf('Invalid base62 character: %s', $char)
                );
            }

            $num = gmp_add(gmp_mul($num, $base), gmp_init($value));
        }

        $raw = gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        if ($raw === '' || $raw === false) {
            $raw = '';
        }

        if (strlen($raw) > self::TOTAL_BYTES) {
            throw new \OverflowException(
                sprintf('Decoded value exceeds %d bytes (got %d)', self::TOTAL_BYTES, strlen($raw))
            );
        }

        return str_pad($raw, self::TOTAL_BYTES, "\x00", STR_PAD_LEFT);
    }
}
