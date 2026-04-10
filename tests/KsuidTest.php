<?php

declare(strict_types=1);

namespace Owpz\Ksuid\Tests;

use Owpz\Ksuid\Ksuid;
use PHPUnit\Framework\TestCase;

class KsuidTest extends TestCase
{
    // =========================================================================
    // Generation
    // =========================================================================

    public function testGenerateReturns27Characters(): void
    {
        $ksuid = Ksuid::generate();
        $encoded = $ksuid->toString();

        $this->assertSame(27, strlen($encoded));
    }

    public function testGenerateProducesUniqueValues(): void
    {
        $ids = [];
        for ($i = 0; $i < 1000; $i++) {
            $ids[] = (string) Ksuid::generate();
        }

        $this->assertCount(1000, array_unique($ids));
    }

    public function testGenerateContainsOnlyBase62Characters(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $ksuid = (string) Ksuid::generate();
            $this->assertMatchesRegularExpression('/^[0-9A-Za-z]{27}$/', $ksuid);
        }
    }

    public function testGenerateTimestampIsReasonable(): void
    {
        $before = time();
        $ksuid = Ksuid::generate();
        $after = time();

        $this->assertGreaterThanOrEqual($before, $ksuid->getTimestamp());
        $this->assertLessThanOrEqual($after, $ksuid->getTimestamp());
    }

    // =========================================================================
    // Lexicographic Sorting
    // =========================================================================

    public function testLexicographicSortability(): void
    {
        $first = Ksuid::fromParts(time(), random_bytes(16));
        $second = Ksuid::fromParts(time() + 10, random_bytes(16));

        $this->assertLessThan((string) $second, (string) $first);
    }

    public function testLexicographicSortabilityBatch(): void
    {
        $ids = [];
        for ($i = 0; $i < 10; $i++) {
            $ids[] = (string) Ksuid::fromParts(
                Ksuid::KSUID_EPOCH + 1000 + ($i * 100),
                random_bytes(16)
            );
        }

        $sorted = $ids;
        sort($sorted);
        $this->assertSame($sorted, $ids, 'KSUIDs with increasing timestamps should be lexicographically sorted');
    }

    // =========================================================================
    // Round-Trip Encode/Decode
    // =========================================================================

    public function testRoundTripEncodeDecode(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $original = Ksuid::generate();
            $encoded = $original->toString();
            $decoded = Ksuid::parse($encoded);

            $this->assertSame($encoded, $decoded->toString());
            $this->assertSame($original->getTimestamp(), $decoded->getTimestamp());
            $this->assertSame($original->getPayload(), $decoded->getPayload());
        }
    }

    public function testRoundTripBytes(): void
    {
        $original = Ksuid::generate();
        $raw = $original->getBytes();

        $this->assertSame(20, strlen($raw));

        $restored = Ksuid::fromBytes($raw);
        $this->assertSame($original->toString(), $restored->toString());
    }

    public function testRoundTripParts(): void
    {
        $now = time();
        $payload = random_bytes(16);
        $ksuid = Ksuid::fromParts($now, $payload);

        $this->assertSame($now, $ksuid->getTimestamp());
        $this->assertSame($payload, $ksuid->getPayload());
    }

    // =========================================================================
    // Timestamp & Payload Extraction
    // =========================================================================

    public function testTimestampExtraction(): void
    {
        $now = time();
        $ksuid = Ksuid::fromParts($now, random_bytes(16));

        $this->assertSame($now, $ksuid->getTimestamp());
    }

    public function testTimestampOffsetExtraction(): void
    {
        $offset = 95004740;
        $payload = hex2bin('669f7efd7b6fe812278486085878563d');
        $ksuid = Ksuid::fromTimestampOffset($offset, $payload);

        $this->assertSame($offset, $ksuid->getTimestampOffset());
        $this->assertSame(Ksuid::KSUID_EPOCH + $offset, $ksuid->getTimestamp());
    }

    public function testPayloadExtraction(): void
    {
        $payload = random_bytes(16);
        $ksuid = Ksuid::fromParts(time(), $payload);

        $this->assertSame($payload, $ksuid->getPayload());
    }

    public function testGetDate(): void
    {
        $now = time();
        $ksuid = Ksuid::fromParts($now, random_bytes(16));
        $date = $ksuid->getDate();

        $this->assertSame($now, $date->getTimestamp());
    }

    // =========================================================================
    // Nil KSUID
    // =========================================================================

    public function testNilKsuid(): void
    {
        $nil = Ksuid::nil();

        $this->assertTrue($nil->isNil());
        $this->assertSame('000000000000000000000000000', $nil->toString());
        $this->assertSame(Ksuid::KSUID_EPOCH, $nil->getTimestamp());
        $this->assertSame(0, $nil->getTimestampOffset());
        $this->assertSame(str_repeat("\x00", 16), $nil->getPayload());
    }

    public function testNonNilKsuidIsNotNil(): void
    {
        $ksuid = Ksuid::generate();
        $this->assertFalse($ksuid->isNil());
    }

    public function testParseNilString(): void
    {
        $nil = Ksuid::parse('000000000000000000000000000');
        $this->assertTrue($nil->isNil());
    }

    // =========================================================================
    // Compare & Equals
    // =========================================================================

    public function testCompare(): void
    {
        $a = Ksuid::fromParts(Ksuid::KSUID_EPOCH + 100, str_repeat("\x00", 16));
        $b = Ksuid::fromParts(Ksuid::KSUID_EPOCH + 200, str_repeat("\x00", 16));

        $this->assertSame(-1, $a->compare($b));
        $this->assertSame(1, $b->compare($a));
        $this->assertSame(0, $a->compare($a));
    }

    public function testCompareWithSameTimestampDifferentPayload(): void
    {
        $a = Ksuid::fromParts(Ksuid::KSUID_EPOCH + 100, str_repeat("\x00", 16));
        $b = Ksuid::fromParts(Ksuid::KSUID_EPOCH + 100, str_repeat("\xFF", 16));

        $this->assertSame(-1, $a->compare($b));
        $this->assertSame(1, $b->compare($a));
    }

    public function testEquals(): void
    {
        $payload = random_bytes(16);
        $now = time();
        $a = Ksuid::fromParts($now, $payload);
        $b = Ksuid::fromParts($now, $payload);

        $this->assertTrue($a->equals($b));
        $this->assertFalse($a->equals(Ksuid::generate()));
    }

    // =========================================================================
    // Next / Prev
    // =========================================================================

    public function testNextIncrementsPayload(): void
    {
        $ksuid = Ksuid::fromTimestampOffset(100, str_repeat("\x00", 16));
        $next = $ksuid->next();

        $this->assertSame(100, $next->getTimestampOffset());
        $this->assertSame(str_repeat("\x00", 15) . "\x01", $next->getPayload());
    }

    public function testNextPayloadOverflowIncrementsTimestamp(): void
    {
        $ksuid = Ksuid::fromTimestampOffset(100, str_repeat("\xFF", 16));
        $next = $ksuid->next();

        $this->assertSame(101, $next->getTimestampOffset());
        $this->assertSame(str_repeat("\x00", 16), $next->getPayload());
    }

    public function testPrevDecrementsPayload(): void
    {
        $ksuid = Ksuid::fromTimestampOffset(100, str_repeat("\x00", 15) . "\x01");
        $prev = $ksuid->prev();

        $this->assertSame(100, $prev->getTimestampOffset());
        $this->assertSame(str_repeat("\x00", 16), $prev->getPayload());
    }

    public function testPrevPayloadUnderflowDecrementsTimestamp(): void
    {
        $ksuid = Ksuid::fromTimestampOffset(100, str_repeat("\x00", 16));
        $prev = $ksuid->prev();

        $this->assertSame(99, $prev->getTimestampOffset());
        $this->assertSame(str_repeat("\xFF", 16), $prev->getPayload());
    }

    public function testPrevOfNilWrapsToMax(): void
    {
        $nil = Ksuid::nil();
        $prev = $nil->prev();

        $this->assertSame(0xFFFFFFFF, $prev->getTimestampOffset());
        $this->assertSame(str_repeat("\xFF", 16), $prev->getPayload());
    }

    public function testNextThenPrevIsIdentity(): void
    {
        $ksuid = Ksuid::generate();
        $roundtrip = $ksuid->next()->prev();

        $this->assertTrue($ksuid->equals($roundtrip));
    }

    public function testPrevThenNextIsIdentity(): void
    {
        $ksuid = Ksuid::generate();
        $roundtrip = $ksuid->prev()->next();

        $this->assertTrue($ksuid->equals($roundtrip));
    }

    public function testNextIsGreaterThanOriginal(): void
    {
        $ksuid = Ksuid::generate();
        $next = $ksuid->next();

        $this->assertSame(-1, $ksuid->compare($next));
    }

    public function testPrevIsLessThanOriginal(): void
    {
        // Use a non-nil KSUID to avoid wrap-around edge case
        $ksuid = Ksuid::fromTimestampOffset(1000, random_bytes(16));
        $prev = $ksuid->prev();

        $this->assertSame(1, $ksuid->compare($prev));
    }

    // =========================================================================
    // ParseOrNull / FromBytesOrNull
    // =========================================================================

    public function testParseOrNullValid(): void
    {
        $ksuid = Ksuid::generate();
        $parsed = Ksuid::parseOrNull($ksuid->toString());

        $this->assertNotNull($parsed);
        $this->assertTrue($ksuid->equals($parsed));
    }

    public function testParseOrNullInvalidLength(): void
    {
        $this->assertNull(Ksuid::parseOrNull('tooshort'));
    }

    public function testParseOrNullInvalidChars(): void
    {
        $this->assertNull(Ksuid::parseOrNull('!!!!!!!!!!!!!!!!!!!!!!!!!!!'));
    }

    public function testFromBytesOrNullValid(): void
    {
        $ksuid = Ksuid::generate();
        $restored = Ksuid::fromBytesOrNull($ksuid->getBytes());

        $this->assertNotNull($restored);
        $this->assertTrue($ksuid->equals($restored));
    }

    public function testFromBytesOrNullInvalid(): void
    {
        $this->assertNull(Ksuid::fromBytesOrNull('short'));
    }

    // =========================================================================
    // Error Cases
    // =========================================================================

    public function testInvalidRawBytesLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Ksuid::fromBytes('short');
    }

    public function testInvalidPayloadLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Ksuid::fromParts(time(), 'short');
    }

    public function testInvalidEncodedLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Ksuid::parse('tooshort');
    }

    public function testInvalidBase62Characters(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Ksuid::parse('!!!!!!!!!!!!!!!!!!!!!!!!!!!');
    }

    public function testTimestampBeforeEpochRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('KSUID epoch');
        Ksuid::fromParts(1000000000, random_bytes(16));
    }

    public function testTimestampOffsetNegativeRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Ksuid::fromTimestampOffset(-1, random_bytes(16));
    }

    public function testTimestampOffsetOverflowRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Ksuid::fromTimestampOffset(0xFFFFFFFF + 1, random_bytes(16));
    }

    // =========================================================================
    // String Casting
    // =========================================================================

    public function testStringCasting(): void
    {
        $ksuid = Ksuid::generate();
        $this->assertSame($ksuid->toString(), (string) $ksuid);
    }

    // =========================================================================
    // fromTimestampOffset
    // =========================================================================

    public function testFromTimestampOffset(): void
    {
        $offset = 12345;
        $payload = random_bytes(16);
        $ksuid = Ksuid::fromTimestampOffset($offset, $payload);

        $this->assertSame($offset, $ksuid->getTimestampOffset());
        $this->assertSame(Ksuid::KSUID_EPOCH + $offset, $ksuid->getTimestamp());
        $this->assertSame($payload, $ksuid->getPayload());
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    public function testZeroTimestampPayload(): void
    {
        $ksuid = Ksuid::fromParts(Ksuid::KSUID_EPOCH, str_repeat("\x00", 16));
        $encoded = $ksuid->toString();

        $this->assertSame(27, strlen($encoded));
        $this->assertSame('000000000000000000000000000', $encoded);
    }

    public function testMaxTimestamp(): void
    {
        $maxTimestamp = Ksuid::KSUID_EPOCH + 0xFFFFFFFF;
        $maxPayload = str_repeat("\xFF", 16);

        $ksuid = Ksuid::fromParts($maxTimestamp, $maxPayload);
        $encoded = $ksuid->toString();

        $this->assertSame(27, strlen($encoded));

        $decoded = Ksuid::parse($encoded);
        $this->assertSame($maxTimestamp, $decoded->getTimestamp());
        $this->assertSame($maxPayload, $decoded->getPayload());
    }

    public function testMaxKsuidString(): void
    {
        // Max KSUID: all bytes 0xFF = "aWgEPTl1tmebfsQzFP4bxwgy80V"
        $maxString = 'aWgEPTl1tmebfsQzFP4bxwgy80V';
        $maxKsuid = Ksuid::parse($maxString);

        $this->assertSame($maxString, $maxKsuid->toString());
        $this->assertSame(0xFFFFFFFF, $maxKsuid->getTimestampOffset());
        $this->assertSame(str_repeat("\xFF", 16), $maxKsuid->getPayload());
    }

    // =========================================================================
    // Go / segment.io Compatibility Test Vectors
    // =========================================================================

    /**
     * @dataProvider goCompatibilityVectors
     */
    public function testGoCompatibilityKnownVectors(
        string $description,
        int $timestampOffset,
        string $payloadHex,
        string $expectedString,
        string $expectedRawHex,
    ): void {
        $payload = hex2bin($payloadHex);
        $ksuid = Ksuid::fromTimestampOffset($timestampOffset, $payload);

        // Verify string encoding
        $this->assertSame(
            $expectedString,
            $ksuid->toString(),
            "$description: string encoding mismatch"
        );

        // Verify raw bytes
        $this->assertSame(
            $expectedRawHex,
            bin2hex($ksuid->getBytes()),
            "$description: raw bytes mismatch"
        );

        // Verify timestamp extraction
        $this->assertSame(
            $timestampOffset,
            $ksuid->getTimestampOffset(),
            "$description: timestamp offset mismatch"
        );

        // Verify payload extraction
        $this->assertSame(
            $payloadHex,
            bin2hex($ksuid->getPayload()),
            "$description: payload extraction mismatch"
        );

        // Verify round-trip parsing
        $parsed = Ksuid::parse($expectedString);
        $this->assertSame(
            $expectedString,
            $parsed->toString(),
            "$description: round-trip string mismatch"
        );
        $this->assertSame(
            $expectedRawHex,
            bin2hex($parsed->getBytes()),
            "$description: round-trip raw bytes mismatch"
        );
        $this->assertSame(
            $timestampOffset,
            $parsed->getTimestampOffset(),
            "$description: round-trip timestamp mismatch"
        );
        $this->assertSame(
            $payloadHex,
            bin2hex($parsed->getPayload()),
            "$description: round-trip payload mismatch"
        );
    }

    public static function goCompatibilityVectors(): array
    {
        return [
            'Standard KSUID with mixed payload' => [
                'Standard KSUID with mixed payload',
                95004740,
                '669f7efd7b6fe812278486085878563d',
                '0o5sKzFDBc56T8mbUP8wH1KpSX7',
                '05a9a844669f7efd7b6fe812278486085878563d',
            ],
            'KSUID with nil (zero) payload' => [
                'KSUID with nil (zero) payload',
                95004740,
                '00000000000000000000000000000000',
                '0o5sKw7Z4xnYVLXEmaUv9lxG0C8',
                '05a9a84400000000000000000000000000000000',
            ],
            'KSUID with max payload' => [
                'KSUID with max payload',
                95004740,
                'ffffffffffffffffffffffffffffffff',
                '0o5sL3ud7B3uapD0WkI3wf4VhoF',
                '05a9a844ffffffffffffffffffffffffffffffff',
            ],
            'KSUID with timestamp at epoch' => [
                'KSUID with timestamp at epoch',
                0,
                '0123456789abcdef0123456789abcdef',
                '000000296tiiBb3U904RIpygpjj',
                '000000000123456789abcdef0123456789abcdef',
            ],
            'KSUID with large timestamp (max int32)' => [
                'KSUID with large timestamp',
                2147483647,
                'deadbeefdeadbeefdeadbeefdeadbeef',
                'IGL7CirdbzjSOihuGRwhdVqH3mh',
                '7fffffffdeadbeefdeadbeefdeadbeefdeadbeef',
            ],
        ];
    }

    // =========================================================================
    // Go Compatibility - Next/Prev Operations
    // =========================================================================

    /**
     * @dataProvider nextPrevVectors
     */
    public function testGoCompatibilityNextPrev(
        string $original,
        string $expectedNext,
        string $expectedPrev,
    ): void {
        $ksuid = Ksuid::parse($original);
        $next = $ksuid->next();
        $prev = $ksuid->prev();

        $this->assertSame(
            $expectedNext,
            $next->toString(),
            "Next operation mismatch for $original"
        );
        $this->assertSame(
            $expectedPrev,
            $prev->toString(),
            "Prev operation mismatch for $original"
        );
    }

    public static function nextPrevVectors(): array
    {
        return [
            'Standard mid-range KSUID' => [
                '0o5sKzFDBc56T8mbUP8wH1KpSX7',
                '0o5sKzFDBc56T8mbUP8wH1KpSX8',
                '0o5sKzFDBc56T8mbUP8wH1KpSX6',
            ],
            'Max payload KSUID' => [
                '0o5sL3ud7B3uapD0WkI3wf4VhoF',
                '0o5sL3ud7B3uapD0WkI3wf4VhoG',
                '0o5sL3ud7B3uapD0WkI3wf4VhoE',
            ],
            'Nil KSUID' => [
                '000000000000000000000000000',
                '000000000000000000000000001',
                'aWgEPTl1tmebfsQzFP4bxwgy80V', // Wraps to max
            ],
        ];
    }

    // =========================================================================
    // Go Compatibility - Edge Cases
    // =========================================================================

    public function testGoCompatibilityEdgeCases(): void
    {
        // Min KSUID (nil)
        $nil = Ksuid::nil();
        $this->assertSame('000000000000000000000000000', $nil->toString());
        $this->assertSame(0, $nil->getTimestampOffset());
        $this->assertSame(str_repeat("\x00", 16), $nil->getPayload());
        $this->assertTrue($nil->isNil());

        // Parse nil KSUID
        $parsedNil = Ksuid::parse('000000000000000000000000000');
        $this->assertTrue($parsedNil->isNil());

        // Max theoretical KSUID
        $maxString = 'aWgEPTl1tmebfsQzFP4bxwgy80V';
        $maxKSUID = Ksuid::parse($maxString);
        $this->assertSame($maxString, $maxKSUID->toString());
        $this->assertSame(4294967295, $maxKSUID->getTimestampOffset());
        $this->assertSame(str_repeat("\xFF", 16), $maxKSUID->getPayload());
    }

    // =========================================================================
    // Go Compatibility - Time Conversion
    // =========================================================================

    public function testGoCompatibilityTimeConversion(): void
    {
        $testCases = [
            ['offset' => 0, 'expectedUnix' => 1400000000],
            ['offset' => 95004740, 'expectedUnix' => 1495004740],
            ['offset' => 4294967295, 'expectedUnix' => 5694967295],
        ];

        foreach ($testCases as $case) {
            $payload = str_repeat("\x00", 16);
            $ksuid = Ksuid::fromTimestampOffset($case['offset'], $payload);

            $this->assertSame(
                $case['expectedUnix'],
                $ksuid->getTimestamp(),
                "Time conversion mismatch for offset {$case['offset']}"
            );
        }
    }

    // =========================================================================
    // Go Compatibility - Base62 Encoding Edge Cases
    // =========================================================================

    public function testGoCompatibilityBase62LeadingZeros(): void
    {
        $smallValue = Ksuid::fromTimestampOffset(0, hex2bin('00000000000000000000000000000001'));
        $smallString = $smallValue->toString();

        $this->assertSame(27, strlen($smallString), 'KSUID strings must always be 27 characters');
        $this->assertStringStartsWith('000000', $smallString, 'Small values should have leading zeros');

        $reparsed = Ksuid::parse($smallString);
        $this->assertSame(0, $reparsed->compare($smallValue), 'Round-trip should preserve value');
    }

    // =========================================================================
    // Go Compatibility - Binary Format
    // =========================================================================

    public function testGoCompatibilityBinaryFormat(): void
    {
        $timestamp = 0x05a9a844; // 95004740
        $payload = hex2bin('669f7efd7b6fe812278486085878563d');
        $ksuid = Ksuid::fromTimestampOffset($timestamp, $payload);

        $buffer = $ksuid->getBytes();

        // First 4 bytes should be timestamp in big-endian
        $this->assertSame($timestamp, unpack('N', substr($buffer, 0, 4))[1]);

        // Next 16 bytes should be the payload
        $this->assertSame($payload, substr($buffer, 4, 16));

        // Total length should be 20
        $this->assertSame(20, strlen($buffer));
    }

    // =========================================================================
    // Go Compatibility - Sorting Behavior
    // =========================================================================

    public function testGoCompatibilitySortingBehavior(): void
    {
        $unsortedStrings = [
            '0o5sKzFDBc56T8mbUP8wH1KpSX7',
            '0o5sKw7Z4xnYVLXEmaUv9lxG0C8',
            '0o5sL3ud7B3uapD0WkI3wf4VhoF',
            '000000000000000000000000000',
            '00000D9NdrD0lJOOhLnBVfvWKK2',
        ];

        $ksuids = array_map(fn (string $s) => Ksuid::parse($s), $unsortedStrings);

        usort($ksuids, fn (Ksuid $a, Ksuid $b) => $a->compare($b));

        $sortedStrings = array_map(fn (Ksuid $k) => $k->toString(), $ksuids);

        $expectedOrder = [
            '000000000000000000000000000',
            '00000D9NdrD0lJOOhLnBVfvWKK2',
            '0o5sKw7Z4xnYVLXEmaUv9lxG0C8',
            '0o5sKzFDBc56T8mbUP8wH1KpSX7',
            '0o5sL3ud7B3uapD0WkI3wf4VhoF',
        ];

        $this->assertSame($expectedOrder, $sortedStrings, 'Sorting order should match Go implementation');
    }

    // =========================================================================
    // Go Compatibility - Comprehensive Round-Trip
    // =========================================================================

    public function testGoCompatibilityComprehensiveRoundTrip(): void
    {
        $testKSUID = Ksuid::parse('0o5sKzFDBc56T8mbUP8wH1KpSX7');

        // String round-trip
        $stringRT = Ksuid::parse($testKSUID->toString());
        $this->assertSame(0, $stringRT->compare($testKSUID));

        // Buffer round-trip
        $bufferRT = Ksuid::fromBytes($testKSUID->getBytes());
        $this->assertSame(0, $bufferRT->compare($testKSUID));

        // Parts round-trip (using offset API)
        $partsRT = Ksuid::fromTimestampOffset(
            $testKSUID->getTimestampOffset(),
            $testKSUID->getPayload()
        );
        $this->assertSame(0, $partsRT->compare($testKSUID));

        // All should be identical
        $this->assertSame($stringRT->toString(), $testKSUID->toString());
        $this->assertSame($bufferRT->toString(), $testKSUID->toString());
        $this->assertSame($partsRT->toString(), $testKSUID->toString());
    }

    // =========================================================================
    // Go Compatibility - parseOrNull Behavior
    // =========================================================================

    public function testGoCompatibilityParseOrNull(): void
    {
        // Valid KSUID should parse normally
        $valid = Ksuid::parseOrNull('0o5sKzFDBc56T8mbUP8wH1KpSX7');
        $this->assertNotNull($valid);
        $this->assertFalse($valid->isNil());

        // Invalid inputs should return null
        $invalidInputs = [
            'invalid',
            '0o5sKzFDBc56T8mbUP8wH1KpSX',    // too short
            '0o5sKzFDBc56T8mbUP8wH1KpSX77',   // too long
            '!@#$%^&*()!@#$%^&*()!@#$%^&',    // invalid characters
        ];

        foreach ($invalidInputs as $invalid) {
            $this->assertNull(
                Ksuid::parseOrNull($invalid),
                "parseOrNull should return null for \"$invalid\""
            );
        }
    }

    // =========================================================================
    // Segment.io Backward Compatibility
    // =========================================================================

    public function testSegmentIoKsuidEpoch(): void
    {
        // Verify our epoch matches the canonical segment.io value
        $this->assertSame(1400000000, Ksuid::KSUID_EPOCH);
    }

    public function testSegmentIoKsuidLength(): void
    {
        // Verify our lengths match
        $this->assertSame(20, Ksuid::TOTAL_BYTES);
        $this->assertSame(27, Ksuid::ENCODED_LENGTH);
        $this->assertSame(4, Ksuid::TIMESTAMP_BYTES);
        $this->assertSame(16, Ksuid::PAYLOAD_BYTES);
    }

    public function testSegmentIoBase62Alphabet(): void
    {
        // The base62 alphabet must match segment.io's:
        // 0-9, A-Z, a-z (standard lexicographic order)
        $ksuid1 = Ksuid::fromTimestampOffset(0, str_repeat("\x00", 15) . "\x3E"); // 62 decimal
        $str = $ksuid1->toString();
        // Value 62 = "10" in base62, so should end in "10"
        $this->assertSame('000000000000000000000000010', $str);
    }

    /**
     * Verify that the hex representation of a known KSUID produces the expected
     * string, matching exactly what segment.io/ksuid would produce.
     */
    public function testSegmentIoKnownKsuid(): void
    {
        // From segment.io docs: the binary representation 0x05a9a844... should
        // produce a specific base62 string
        $raw = hex2bin('05a9a844669f7efd7b6fe812278486085878563d');
        $ksuid = Ksuid::fromBytes($raw);

        $this->assertSame('0o5sKzFDBc56T8mbUP8wH1KpSX7', $ksuid->toString());
    }

    // =========================================================================
    // Stress / Fuzz-like Tests
    // =========================================================================

    public function testManyRoundTrips(): void
    {
        for ($i = 0; $i < 500; $i++) {
            $ksuid = Ksuid::generate();
            $encoded = $ksuid->toString();
            $decoded = Ksuid::parse($encoded);

            $this->assertSame($encoded, $decoded->toString(), "Round-trip failed at iteration $i");
            $this->assertTrue($ksuid->equals($decoded), "Equality failed at iteration $i");
        }
    }

    public function testRandomPayloadsWithFixedTimestamp(): void
    {
        $offset = 100000;
        for ($i = 0; $i < 100; $i++) {
            $payload = random_bytes(16);
            $ksuid = Ksuid::fromTimestampOffset($offset, $payload);

            $decoded = Ksuid::parse($ksuid->toString());
            $this->assertSame($offset, $decoded->getTimestampOffset());
            $this->assertSame(bin2hex($payload), bin2hex($decoded->getPayload()));
        }
    }

    public function testNextPrevChain(): void
    {
        $start = Ksuid::generate();
        $current = $start;

        // Go forward 100 steps
        for ($i = 0; $i < 100; $i++) {
            $current = $current->next();
        }

        // Come back 100 steps
        for ($i = 0; $i < 100; $i++) {
            $current = $current->prev();
        }

        $this->assertTrue($start->equals($current), 'Forward 100 + backward 100 should return to start');
    }

    public function testMonotonicallyIncreasingSequence(): void
    {
        $base = Ksuid::fromTimestampOffset(50000, str_repeat("\x00", 16));
        $prev = $base;

        for ($i = 0; $i < 100; $i++) {
            $next = $prev->next();
            $this->assertSame(-1, $prev->compare($next), "KSUID $i should be less than KSUID " . ($i + 1));
            $prev = $next;
        }
    }
}
