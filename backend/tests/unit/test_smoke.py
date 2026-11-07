def test_package_imports():
    import backend

    assert callable(backend.main)
