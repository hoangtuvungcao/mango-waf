import re

with open('api/dashboard.go', 'r', encoding='utf-8') as f:
    content = f.read()

# Add X-Accel-Buffering
content = content.replace(
    'w.Header().Set("Connection", "keep-alive")',
    'w.Header().Set("Connection", "keep-alive")\n\tw.Header().Set("X-Accel-Buffering", "no")'
)

# Add Keep-Alive Ping
ping_code = """			logs := core.GetLogStore().QueryLogs("", "", "")
			if len(logs) == 0 {
				fmt.Fprintf(w, ": keepalive\\n\\n")
				flusher.Flush()
				continue
			}"""
content = content.replace(
    'logs := core.GetLogStore().QueryLogs("", "", "")\n\t\t\tif len(logs) == 0 {\n\t\t\t\tcontinue\n\t\t\t}',
    ping_code
)

with open('api/dashboard.go', 'w', encoding='utf-8') as f:
    f.write(content)
print("SSE Fixed")
