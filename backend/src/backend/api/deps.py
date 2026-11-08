from collections.abc import Iterator
from typing import Annotated

from duckdb import DuckDBPyConnection
from fastapi import Depends, Request


def get_db(request: Request) -> Iterator[DuckDBPyConnection]:
    """One cursor per request; DuckDB supports concurrent threads through cursors."""
    cur = request.app.state.db.cursor()
    try:
        yield cur
    finally:
        cur.close()


Db = Annotated[DuckDBPyConnection, Depends(get_db)]
