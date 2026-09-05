package com.company.remoteaccess.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Minimal YAML-subset parser/serializer for the application configuration file.
 *
 * <p>Supported: nested maps by indentation, inline string lists {@code [a, b]},
 * comments, and all scalars (string, quoted string, int, double, boolean, null).
 * The serializer only emits the subset the parser understands.
 */
public final class Yaml {

    private Yaml() {
    }

    private record Frame(int indent, boolean isList, Object container) {
    }

    // ------------------------------------------------------------------
    // parse
    // ------------------------------------------------------------------

    public static Map<String, Object> parse(String text) {
        Map<String, Object> root = new LinkedHashMap<>();
        if (text == null || text.isBlank()) {
            return root;
        }
        List<Frame> stack = new ArrayList<>();
        stack.add(new Frame(-1, false, root));

        for (String raw : text.replace("\r\n", "\n").split("\n", -1)) {
            String line = stripComment(raw);
            if (line.isBlank()) {
                continue;
            }
            int indent = leadingSpaces(line);
            String content = line.substring(indent);

            if (content.startsWith("- ")) {
                // attach to the list frame that owns this indent level
                while (stack.size() > 1 && stack.get(stack.size() - 1).indent() >= indent) {
                    stack.remove(stack.size() - 1);
                }
                Frame listFrame = stack.get(stack.size() - 1);
                if (!listFrame.isList() || listFrame.indent() > indent) {
                    throw new IllegalArgumentException("list item without list context: " + line);
                }
                @SuppressWarnings("unchecked")
                List<Object> list = (List<Object>) listFrame.container();
                list.add(parseScalar(content.substring(2).trim()));
                continue;
            }

            int colon = content.indexOf(':');
            if (colon < 0) {
                throw new IllegalArgumentException("invalid YAML line: " + line);
            }
            String key = unquote(content.substring(0, colon).trim());
            String rest = content.substring(colon + 1).trim();

            while (stack.size() > 1 && stack.get(stack.size() - 1).indent() >= indent) {
                stack.remove(stack.size() - 1);
            }
            Map<String, Object> current = currentMap(stack);

            if (rest.isEmpty()) {
                Map<String, Object> child = new LinkedHashMap<>();
                current.put(key, child);
                stack.add(new Frame(indent, false, child));
            } else if (rest.startsWith("[")) {
                current.put(key, parseList(rest));
            } else {
                current.put(key, parseScalar(rest));
            }
        }
        return root;
    }

    private static Map<String, Object> currentMap(List<Frame> stack) {
        Frame top = stack.get(stack.size() - 1);
        if (top.isList()) {
            throw new IllegalArgumentException("scalar under list not supported");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) top.container();
        return m;
    }

    private static List<String> parseList(String s) {
        String inner = s.trim();
        if (!inner.endsWith("]") || !inner.startsWith("[")) {
            throw new IllegalArgumentException("invalid inline list: " + s);
        }
        inner = inner.substring(1, inner.length() - 1).trim();
        if (inner.isEmpty()) {
            return new ArrayList<>();
        }
        List<String> items = new ArrayList<>();
        for (String part : inner.split(",")) {
            items.add(unquote(part.trim()));
        }
        return items;
    }

    // ------------------------------------------------------------------
    // serialize
    // ------------------------------------------------------------------

    public static String serialize(Map<String, Object> root) {
        StringBuilder sb = new StringBuilder();
        writeMap(root, sb, 0);
        return sb.toString();
    }

    private static void writeMap(Map<String, Object> map, StringBuilder sb, int indent) {
        map.forEach((key, value) -> {
            if (value instanceof Map<?, ?> child) {
                writeIndent(sb, indent);
                sb.append(key).append(":\n");
                writeMap(cast(child), sb, indent + 2);
            } else if (value instanceof List<?> list) {
                writeIndent(sb, indent);
                sb.append(key).append(": ");
                sb.append('[');
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) {
                        sb.append(", ");
                    }
                    sb.append(scalar(list.get(i)));
                }
                sb.append(']').append('\n');
            } else {
                writeIndent(sb, indent);
                sb.append(key).append(": ").append(scalar(value)).append('\n');
            }
        });
    }

    // ------------------------------------------------------------------
    // scalars
    // ------------------------------------------------------------------

    private static Object parseScalar(String s) {
        String v = s.trim();
        if (v.isEmpty() || v.equals("~") || v.equals("null")) {
            return null;
        }
        if (v.startsWith("\"") && v.endsWith("\"") && v.length() >= 2) {
            return v.substring(1, v.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\");
        }
        if (v.equals("true") || v.equals("True") || v.equals("TRUE")) {
            return true;
        }
        if (v.equals("false") || v.equals("False") || v.equals("FALSE")) {
            return false;
        }
        if (Pattern.matches("-?\\d+", v)) {
            try {
                return Long.parseLong(v);
            } catch (NumberFormatException ignored) {
                return v;
            }
        }
        if (Pattern.matches("-?\\d+\\.\\d+", v)) {
            try {
                return Double.parseDouble(v);
            } catch (NumberFormatException ignored) {
                return v;
            }
        }
        return v;
    }

    private static String scalar(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String s) {
            if (s.isEmpty() || s.contains(": ") || s.startsWith("#")
                    || s.contains("\n") || s.contains("[")) {
                return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
            }
            return s;
        }
        return String.valueOf(value);
    }

    private static String unquote(String s) {
        if (s.length() >= 2) {
            if ((s.startsWith("\"") && s.endsWith("\""))
                    || (s.startsWith("'") && s.endsWith("'"))) {
                return s.substring(1, s.length() - 1);
            }
        }
        return s;
    }

    private static int leadingSpaces(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == ' ') {
            i++;
        }
        return i;
    }

    private static String stripComment(String line) {
        boolean inQuote = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"' && (i == 0 || line.charAt(i - 1) != '\\')) {
                inQuote = !inQuote;
            }
            if (c == '#' && !inQuote) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private static void writeIndent(StringBuilder sb, int indent) {
        sb.append(" ".repeat(indent));
    }

    private static Map<String, Object> cast(Map<?, ?> m) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) {
            out.put(String.valueOf(e.getKey()), e.getValue());
        }
        return out;
    }
}