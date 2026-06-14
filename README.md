# bsky_queue_manager

A WIP queue system for Bluesky (or Blacksky, etc.). The name 'queuesky' in the code is a placeholder; a more creative pun will be added at a later date.

## The codebase

This is a Django project using Poetry for dependency management. Check `bsky_queue_manager/` for the app code.

`bsky_queue_manager/atproto` has a rudimentary implementation of OAuth via an ATProto PDS. It currently uses the `http://localhost` special case for its client ID, which makes it not suitable for production without some tweaks (see: [https://atproto.com/specs/oauth#localhost-client-development](https://atproto.com/specs/oauth#localhost-client-development)).
