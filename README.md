# Dissectors
Dissectors for analyzing RA3 traffic, written in lua.
## Usage example
1. Clone this repository to anywhere
```
D:\lanyi\Source\Repos> git clone https://github.com/RA3BattleNet/Dissectors
```
2. Load `index.lua` from your lua plugin:
```lua
-- See https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html
-- Wireshark/plugins/ra3.lua:
local base_path = [[D:\lanyi\Source\Repos\Dissectors\]]
dofile(base_path .. 'index.lua')(base_path)
```