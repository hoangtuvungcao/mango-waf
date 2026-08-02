import re

with open('api/dashboard_v2.go', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add CSS media query for .domain-actions
css_fix = """
.domain-actions{display:flex;gap:8px}

@media(max-width:768px){
  .domain-row{flex-direction:column;align-items:flex-start;gap:12px}
  .domain-actions{width:100%;justify-content:flex-end}
}
"""
content = content.replace('.domain-actions{display:flex;gap:8px}', css_fix)

# 2. Add class="domain-actions" to the action div in the JS string
content = content.replace(
    "'<div style=\"display:flex;align-items:center;gap:10px;flex-wrap:wrap\">' +",
    "'<div class=\"domain-actions\" style=\"display:flex;align-items:center;gap:10px;flex-wrap:wrap\">' +"
)

# 3. Carefully replace SVGs in the JS strings ONLY.
# Edit icon: title="Edit"><svg ... </svg></button>
content = re.sub(
    r'title="Edit"><svg.*?<\/svg><\/button>',
    'title="Edit">Edit</button>',
    content
)

# Delete icon: title="Delete"><svg ... </svg></button>
content = re.sub(
    r'title="Delete"><svg.*?<\/svg><\/button>',
    'title="Delete">Delete</button>',
    content
)

# Remove backend icon: title="Remove"><svg ... </svg></button>
content = re.sub(
    r'title="Remove"><svg.*?<\/svg><\/button>',
    'title="Remove">X</button>',
    content
)

# Toast icons (success, error, info)
content = re.sub(r'success: \'<svg.*?<\/svg>\',', "success: 'OK',", content)
content = re.sub(r'error: \'<svg.*?<\/svg>\',', "error: 'ERR',", content)
content = re.sub(r'info: \'<svg.*?<\/svg>\'', "info: 'INFO'", content)

with open('api/dashboard_v2.go', 'w', encoding='utf-8') as f:
    f.write(content)
print("Dashboard fixed!")
