import os
import sys
from pathlib import Path

os.environ["REGISTRO_ACCESOS"] = "/tmp/atenea_pruebas/accesos.csv"   # las pruebas no tocan el registro real
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
