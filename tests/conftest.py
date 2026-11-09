import sys
from pathlib import Path
import shutil, uuid
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))

@pytest.fixture
def tmp_path(request):
    """Keep test scratch space under the writable test tree on restricted Windows hosts."""
    parent=Path(request.node.path).parent
    path=parent/("scratch-"+uuid.uuid4().hex)
    path.mkdir()
    try: yield path
    finally: shutil.rmtree(path,ignore_errors=True)

