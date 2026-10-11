const NUMERIC_TOKEN_MARKER = '__zk_native_u64_token__:';

// Native serde_json envelopes encode u64 values as JSON numbers. Mark only long integer tokens
// which occur outside JSON strings before parsing so string fields (including all-decimal salts)
// are never mistaken for BigInt values.
function markLongIntegerTokens(source) {
  let output = '';
  let inString = false;
  let escaped = false;

  for (let index = 0; index < source.length;) {
    const character = source[index];
    if (inString) {
      output += character;
      index += 1;
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      output += character;
      index += 1;
      continue;
    }
    if (character >= '0' && character <= '9') {
      let end = index + 1;
      while (end < source.length && source[end] >= '0' && source[end] <= '9') end += 1;
      const token = source.slice(index, end);
      output += token.length >= 16 ? `"${NUMERIC_TOKEN_MARKER}${token}"` : token;
      index = end;
      continue;
    }
    output += character;
    index += 1;
  }
  return output;
}

export function parseEnvelope(source) {
  return JSON.parse(markLongIntegerTokens(source), (_, item) => {
    if (typeof item !== 'string' || !item.startsWith(NUMERIC_TOKEN_MARKER)) return item;
    const digits = item.slice(NUMERIC_TOKEN_MARKER.length);
    if (!/^\d{16,}$/.test(digits)) throw new SyntaxError('invalid marked integer token');
    return BigInt(digits);
  });
}
