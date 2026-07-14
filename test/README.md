# Testing aes_tools

SQL tests for this extension are written as DuckDB SQLLogicTests in the `sql` directory.

Run the release tests with:

```shell
make test
```

Or run the debug tests with:

```shell
make test_debug
```

Before committing, also run the repository's formatting and static-analysis checks:

```shell
make format-check
make tidy-check
```
