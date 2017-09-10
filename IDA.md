# IDA plugin installation
The IDA plugin is in the src/IDA/grap/ folder, you need to copy it into IDA's plugin folder.
For instance on Windows:

- grap.py into C:\Program Files (x86)\IDA\plugins\
- idagrap/ into C:\Program Files (x86)\IDA\plugins\

# Usage
You can activate the plugin within IDA with the menu (Edit -> Plugins -> IDAgrap) or with Shift+G.

It opens a new tab with two panels.

- The first panel is made for detection and has two buttons: one for launching detection, the other for coloring matched nodes.
- The second panel will assist the creation of new patterns within IDA. You first need to "Load the control flow graph", then click right on the instruction you want to define as the root of your pattern (in IDA View), select "[grap] set root node", select additional nodes, then use the plugin buttons to generate the pattern.
