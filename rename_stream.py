import re

# dashboard.go
with open('api/dashboard.go', 'r', encoding='utf-8') as f:
    c = f.read()
c = c.replace('"/api/attack-stream"', '"/api/events/security"')
with open('api/dashboard.go', 'w', encoding='utf-8') as f:
    f.write(c)

# dashboard_v2.go
with open('api/dashboard_v2.go', 'r', encoding='utf-8') as f:
    c = f.read()
c = c.replace("'/api/attack-stream'", "'/api/events/security'")
with open('api/dashboard_v2.go', 'w', encoding='utf-8') as f:
    f.write(c)

print("Renamed to /api/events/security")
