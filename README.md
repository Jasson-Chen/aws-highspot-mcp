# Highspot MCP Server

MCP server to access public data on AWS Highspot.

## 📦 Prerequisites

- Python 3.10+
- `uv` package manager
- AWS Midway authentication using `mwinit -o`


## Tools

- `get_highspot_info()` - Check authentication status
- `search_highspot(query)` - Search Highspot content

## MCP Client Configuration

Add to your MCP client configuration:

```json
{
    "mcpServers": {
        "aws_highspot_mcp": {
            "command": "uvx",
            "args": [
                "--from",
                "git+https://github.com/Jasson-Chen/aws-highspot-mcp.git@main",
                "highspot-mcp"
            ]
        }
    }
}
```

## Author

- **Yunqi Chen** - [yunqic@amazon.com](mailto:yunqic@amazon.com)


## References

- [Amzn_Req](https://w.amazon.com/bin/view/Users/mikohei/python/amzn_req/)

- [Mentor](https://w.amazon.com/bin/view/Mentor/)





