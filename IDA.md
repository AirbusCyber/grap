# Requirements
You will need to have grap installed (see [WINDOWS.md](WINDOWS.md) for Windows, and [README.md](README.md) for GNU/Linux).

# IDA plugin installation
You need to copy the following file and folder into IDA's plugin folder.
For instance for IDA 7 on Windows:

- grap.py into C:\Program Files\IDA 7.0\plugins\
- idagrap/ into C:\Program Files\IDA 7.0\plugins\

These files can be found either in the pre-compiled binaries or in the repository (src/IDA/grap/)[src/IDA/grap/].

# Usage
You can activate the plugin within IDA with the menu (Edit -> Plugins -> IDAgrap) or with Shift+G.

It opens a new tab with three panels.

* The first panel is made for detection and has two buttons: one for launching detection, the other for coloring matched nodes.
    * Some patterns are already available
    * You can modify them and add your own in the folder C:\Program Files\IDA 7.0\plugins\idagrap\patterns\test\misc\files
    
* The second panel will assist the creation of new patterns within IDA:
    * Click "Load the control flow graph"
    * In IDA View (main panel), click right on the instruction you want to define as the root of your pattern , select "[grap] set root node"
    * Define additional nodes with right click + "[grap] Add target node"
    * Use the plugin buttons to generate the pattern

* An "About" panel
