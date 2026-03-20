def main() -> None:
    from model_safety_mcp.server import create_server

    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
