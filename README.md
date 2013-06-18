# gpg-mailgate

I'm not the author of this tool, only bugfixer. Original code can be found on [project google code page](http://code.google.com/p/gpg-mailgate/).

[Lefty] This script now only functions with Postfix's Delivered-To: header.  This seems to be the only way to get a useful recipient list, as parsing the To/Cc/Bcc headers is unreliable - it can contain addresses we may not want to deliver to.
[Lefty] To configure postfix for this, add the "D" flag to the master.cf entry for your gpg-mailgate filter.
[Lefty] Example:
gpg-mailgate   unix -   n       n       -       -       pipe
  flags=D user=gpgmap argv=/usr/local/bin/gpg-mailgate.py

[Lefty] Also, in main.cf, ensure you have a recipient limit of 1 for your content filter.
[Lefty] Example:
content_filter = gpg-mailgate
gpg-mailgate_destination_recipient_limit = 1

# TODO
- ~~attachments support~~
- multipart messages support
- testing
