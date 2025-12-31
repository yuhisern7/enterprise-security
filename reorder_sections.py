#!/usr/bin/env python3
"""
Reorder HTML sections to match their numbering (1-21 in sequence)
"""
import re

html_file = "AI/inspector_ai_monitoring.html"

# Read the file
with open(html_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Find all section blocks with their numbers
# Pattern: <!-- ======== SECTION X: --> ... </section>
section_pattern = r'(      <!-- [^\n]*\n      <!-- ={40,}\n         SECTION (\d+):.*?\n.*?<!-- Information Panel -->|      <!-- [^\n]*\n      <!-- ={40,}\n           SECTION (\d+):.*?)\n.*?</section>'

sections = {}
matches = list(re.finditer(section_pattern, content, re.DOTALL))

print(f"Found {len(matches)} section blocks")

# Extract section number and content for each match
for match in matches:
    section_num = match.group(2) or match.group(3)
    if section_num:
        section_num = int(section_num)
        section_content = match.group(0)
        sections[section_num] = section_content
        print(f"  Section {section_num}: {len(section_content)} chars")

# Find the position where sections start (after first section)
first_section_end = content.find('</section>', content.find('SECTION 1:')) + len('</section>')
sections_start = first_section_end

# Find where sections end (before the closing </main> or script tags)
last_section_end = content.rfind('</section>', 0, content.find('</main>')) + len('</section>')

# Keep everything before the first section ends
before_sections = content[:sections_start]

# Keep everything after last section
after_sections = content[last_section_end:]

# Rebuild in correct order (2-21, section 1 already in place)
reordered_content = before_sections
for i in range(2, 22):
    if i in sections:
        reordered_content += '\n\n' + sections[i]
    else:
        print(f"WARNING: Section {i} not found!")

reordered_content += after_sections

# Write back
with open(html_file, 'w', encoding='utf-8') as f:
    f.write(reordered_content)

print(f"\n✅ Sections reordered successfully!")
print(f"Total file size: {len(reordered_content):,} chars")
