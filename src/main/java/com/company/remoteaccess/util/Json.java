package com.company.remoteaccess.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON parser/serializer (no external dependency). Supported values:
 * objects, arrays, strings, numbers, booleans, null.
 */
public final class Json {

    private Json() {
    }

    /** Node view of a JSON object. */
    public static final class JsonObject {
        private final Map<String, Object> data;

        private JsonObject(Map<String, Object> data) {
            this.data = data;
        }

        public String get(String key) {
            Object v = data.get(key);
            if (v == null) {
                return null;
            }
            return String.valueOf(v);
        }

        public boolean has(String key) {
            return data.containsKey(key);
        }

        public JsonObject getObject(String key) {
            Object v = data.get(key);
            return v instanceof Map<?, ?> m ? new JsonObject(castMap(m)) : null;
        }

        public List<JsonObject> getList(String key) {
            Object v = data.get(key);
            if (!(v instanceof List<?> list)) {
                return null;
            }
            List<JsonObject> out = new ArrayList<>();
            for (Object o : list) {
                if (o instanceof Map<?, ?> m) {
                    out.add(new JsonObject(castMap(m)));
                }
            }
            return out;
        }

        public Map<String, Object> raw() {
            return data;
        }
    }

    public static JsonObject parseObject(String json) {
        Object v = parse(json);
        if (!(v instanceof Map<?, ?> m)) {
            throw new IllegalArgumentException("expected JSON object");
        }
        return new JsonObject(castMap(m));
    }

    public static List<JsonObject> parseArray(String json) {
        Object v = parse(json);
        if (!(v instanceof List<?> list)) {
            throw new IllegalArgumentException("expected JSON array");
        }
        List<JsonObject> out = new ArrayList<>();
        for (Object o : list) {
            if (o instanceof Map<?, ?> m) {
                out.add(new JsonObject(castMap(m)));
            }
        }
        return out;
    }

    public static Object parse(String json) {
        Parser p = new Parser(json);
        Object v = p.parseValue();
        p.skipWs();
        if (!p.atEnd()) {
            throw new IllegalArgumentException("trailing characters in JSON");
        }
        return v;
    }

    public static String serialize(Object value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString();
    }

    private static void write(Object v, StringBuilder sb) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    default -> {
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                    }
                }
            }
            sb.append('"');
        } else if (v instanceof Boolean b) {
            sb.append(b);
        } else if (v instanceof Number n) {
            sb.append(n);
        } else if (v instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                write(String.valueOf(e.getKey()), sb);
                sb.append(':');
                write(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof List<?> list) {
            sb.append('[');
            boolean first = true;
            for (Object o : list) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                write(o, sb);
            }
            sb.append(']');
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Map<?, ?> m) {
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) {
            out.put(String.valueOf(e.getKey()), e.getValue());
        }
        return out;
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return pos >= s.length();
        }

        void skipWs() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
                pos++;
            }
        }

        Object parseValue() {
            skipWs();
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of JSON");
            }
            char c = s.charAt(pos);
            return switch (c) {
                case '{' -> parseObjectBody();
                case '[' -> parseArrayBody();
                case '"' -> parseString();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default -> parseNumber();
            };
        }

        private Object parseObjectBody() {
            pos++; // {
            Map<String, Object> map = new HashMap<>();
            skipWs();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                Object key = parseValue();
                skipWs();
                expect(':');
                Object value = parseValue();
                map.put(String.valueOf(key), value);
                skipWs();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return map;
                } else {
                    throw new IllegalArgumentException("expected ',' or '}' in object");
                }
            }
        }

        private List<Object> parseArrayBody() {
            pos++; // [
            List<Object> list = new ArrayList<>();
            skipWs();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWs();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    return list;
                } else {
                    throw new IllegalArgumentException("expected ',' or ']' in array");
                }
            }
        }

        private String parseString() {
            pos++; // "
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw new IllegalArgumentException("unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (atEnd()) {
                        throw new IllegalArgumentException("unterminated escape");
                    }
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > s.length()) {
                                throw new IllegalArgumentException("bad unicode escape");
                            }
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                            pos += 4;
                        }
                        default -> throw new IllegalArgumentException("bad escape: " + e);
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        private Object parseNumber() {
            int start = pos;
            while (pos < s.length()
                    && (Character.isDigit(s.charAt(pos)) || s.charAt(pos) == '-'
                    || s.charAt(pos) == '+' || s.charAt(pos) == '.'
                    || s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                pos++;
            }
            String num = s.substring(start, pos);
            try {
                if (num.contains(".") || num.contains("e") || num.contains("E")) {
                    return Double.parseDouble(num);
                }
                return Long.parseLong(num);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid number: " + num);
            }
        }

        private Object parseLiteral(String literal, Object value) {
            if (!s.startsWith(literal, pos)) {
                throw new IllegalArgumentException("invalid literal");
            }
            pos += literal.length();
            return value;
        }

        private char peek() {
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of JSON");
            }
            return s.charAt(pos);
        }

        private void expect(char c) {
            if (atEnd() || s.charAt(pos) != c) {
                throw new IllegalArgumentException("expected '" + c + "'");
            }
            pos++;
        }
    }
}