"""Freezer entry; package imports and source-authentication assets are bundled."""
from wechat_capture_next.product_host import main

if __name__ == '__main__':
    import sys
    if sys.argv[1:]==['--media-worker']:
        from wechat_capture_next.media_decode import main as media_main
        raise SystemExit(media_main())
    if sys.argv[1:2] == ['--cli']:
        from wechat_capture_next.__main__ import main as cli_main
        del sys.argv[1]
        raise SystemExit(cli_main())
    if sys.argv[1:2] == ['--configure']:
        from wechat_capture_next.first_run import main as configure_main
        raise SystemExit(configure_main(sys.argv[2:]))
    raise SystemExit(main())
