from pathlib import Path
import sys
root=Path(__file__).resolve().parents[1]
source=root/'source' if (root/'source'/'syntal_sso').exists() else root
sys.path.insert(0,str(source))
