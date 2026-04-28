# Malware Analysis Tools

This directory contains all malware analysis tool wrappers organized into separate modules.

## Structure

- `base.py` - Base class `MalwareAnalysisTool` for all tools
- `die_tool.py` - Detect-it-Easy (DiE) tool wrapper
- `pestudio_tool.py` - PE-Studio tool wrapper
- `strings_tool.py` - Strings extraction tool wrapper
- `fileinfo_tool.py` - Basic file information tool
- `toolkit.py` - `MalwareAnalysisToolkit` orchestrator class
- `__init__.py` - Package initialization and exports

## Usage

```python
from tools import MalwareAnalysisToolkit

# Initialize toolkit
toolkit = MalwareAnalysisToolkit()

# Run analysis on a file
results = toolkit.analyze_file(
    file_path="path/to/file.exe",
    output_dir="output_directory",
    tools=["die", "pestudio", "strings", "fileinfo"]  # or None for all
)
```

## Individual Tools

You can also use individual tools:

```python
from tools import DetectItEasyTool, PEStudioTool, StringsTool, FileInfoTool

# Use individual tools
die = DetectItEasyTool()
result = die.run("file.exe", "output_dir")
```

## Adding New Tools

To add a new tool:

1. Create a new file (e.g., `new_tool.py`)
2. Inherit from `MalwareAnalysisTool` in `base.py`
3. Implement the `run()` method
4. Add it to `toolkit.py` in the `__init__` method
5. Export it in `__init__.py`


