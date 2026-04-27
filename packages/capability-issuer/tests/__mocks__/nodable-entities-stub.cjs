/**
 * CommonJS stub for the pure-ESM `@nodable/entities` package, which is pulled
 * in transitively by the AWS SDK's `fast-xml-parser` dependency.
 *
 * Tests in this package mock all AWS KMS calls, so the actual XML entity
 * decoder is never exercised at runtime. We only need a CommonJS module that
 * Jest can `require()` without parse errors.
 *
 * The shapes returned here mirror just enough of the real API surface that
 * `fast-xml-parser` can be imported successfully under Node's CommonJS loader.
 */

class EntityDecoder {
  constructor() {}
  write() { return 0; }
  end() { return 0; }
}

class EntityEncoder {
  constructor() {}
  encode(input) { return String(input); }
}

const emptyMap = Object.freeze({});

module.exports = {
  EntityDecoder,
  EntityEncoder,
  COMMON_HTML: emptyMap,
  XML: emptyMap,
  ALL_ENTITIES: emptyMap,
  ARROWS: emptyMap,
  BASIC_LATIN: emptyMap,
  CURRENCY: emptyMap,
  MATH: emptyMap,
  MATH_ADVANCED: emptyMap,
  CYRILLIC: emptyMap,
  FRACTIONS: emptyMap,
  GREEK: emptyMap,
  LATIN_ACCENTS: emptyMap,
  LATIN_EXTENDED: emptyMap,
  MISC_SYMBOLS: emptyMap,
  PUNCTUATION: emptyMap,
  SHAPES: emptyMap,
};
