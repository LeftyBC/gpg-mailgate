#!/usr/bin/python

from ConfigParser import RawConfigParser
from email.mime.base import MIMEBase
import email
import email.message
import re
import GnuPG
import smtplib
import sys

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read('/etc/gpg-mailgate.conf')
cfg = dict()
for sect in _cfg.sections():
	cfg[sect] = dict()
	for (name, value) in _cfg.items(sect):
		cfg[sect][name] = value


if cfg.has_key('default') and cfg['default'].has_key('recipient_delimiter'):
	recipient_delimiter = cfg['default']['recipient_delimiter']
else:
	recipient_delimiter = None

# Read e-mail from stdin
raw = sys.stdin.read()
raw_message = email.message_from_string( raw )

from_addr = raw_message['From']
to_addrs = list()
encrypted_to_addrs = list()
if raw_message.has_key('Delivered-To'):
	to_addrs.extend( [e[1] for e in email.utils.getaddresses([raw_message['Delivered-To']])] )
	del raw_message['Delivered-To']
#if raw_message.has_key('To'):
#	to_addrs.extend( [e[1] for e in email.utils.getaddresses([raw_message['To']])] )
#if raw_message.has_key('Cc'):
#	to_addrs.extend( [e[1] for e in email.utils.getaddresses([raw_message['Cc']])] )
#if raw_message.has_key('Bcc'):
#	to_addrs.extend( [e[1] for e in email.utils.getaddresses([raw_message['Bcc']])] )
#if raw_message.has_key('X-GPG-Encrypt-Cc'):
#        encrypted_to_addrs.extend( [e[1] for e in email.utils.getaddresses([raw_message['X-GPG-Encrypt-Cc']])] )
#	del raw_message['X-GPG-Encrypt-Cc']

def emit_log(message):
	if cfg.has_key('logging') and cfg['logging'].has_key('file'):
		message = message.rstrip()
		log = open(cfg['logging']['file'], 'a')
		log.write("%s\n" % (message))
		log.close()

def send_msg( message, recipients = None ):
	if recipients == None or len(recipients) < 1:
		emit_log("No recipients found for this message:\n%s" % message)
		return
	emit_log("Sending email to: <%s>\n" % '> <'.join( recipients ))
	relay = (cfg['relay']['host'], int(cfg['relay']['port']))
	smtp = smtplib.SMTP(relay[0], relay[1])
	smtp.sendmail( from_addr, recipients, message.as_string() )

def encrypt_payload( payload, gpg_to_cmdline ):
	gpg = GnuPG.GPGEncryptor( cfg['gpg']['keyhome'], gpg_to_cmdline )
	raw_payload = payload.get_payload(decode=True)
	gpg.update( raw_payload )
	payload.set_payload( gpg.encrypt() )
	if payload['Content-Disposition']:
		payload.replace_header( 'Content-Disposition', re.sub(r'filename="([^"]+)"', r'filename="\1.pgp"', payload['Content-Disposition']) )
	if payload['Content-Type']:
		payload.replace_header( 'Content-Type', re.sub(r'name="([^"]+)"', r'name="\1.pgp"', payload['Content-Type']) )
		if payload.get_content_type() != 'text/plain' and payload.get_content_type != 'text/html':
			payload.replace_header( 'Content-Type', re.sub(r'^[a-z/]+;', r'application/octet-stream;', payload['Content-Type']) )
			payload.set_payload( "\n".join( filter( lambda x:re.search(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$',x), payload.get_payload().split("\n") ) ) )
	return payload

def encrypt_all_payloads( payloads, gpg_to_cmdline ):
	encrypted_payloads = list()
	if type( payloads ) == str:
		msg = email.message.Message()
		msg.set_payload( payloads )
		return encrypt_payload( msg, gpg_to_cmdline ).as_string()
	for payload in payloads:
		if( type( payload.get_payload() ) == list ):
			encrypted_payloads.append( encrypt_all_payloads( payload.get_payload(), gpg_to_cmdline ) )
		else:
			encrypted_payloads.append( [encrypt_payload( payload, gpg_to_cmdline )] )
	return sum(encrypted_payloads, [])

def get_msg( message ):
	if not message.is_multipart():
		return message.get_payload()
	return '\n\n'.join( [str(m) for m in message.get_payload()] )


keys = GnuPG.public_keys( cfg['gpg']['keyhome'] )
gpg_to = list()
ungpg_to = list()

emit_log('encrypted recipients to process: %s' % ', '.join(encrypted_to_addrs))
for enc in encrypted_to_addrs:
	addr,domain = enc.split('@')
	if recipient_delimiter is not None and recipient_delimiter in addr:
		# we have a delimiter!
		real_addr = addr.split(recipient_delimiter)[0] # only the left hand side
		newenc = "%s@%s" % (real_addr,domain)
	else:
		newenc = enc

	if domain in cfg['default']['domains'].split(','):
		if enc in keys:
			# if the key matches directly, we can encrypt to this address
			emit_log("Adding encrypted recipient %s" % (enc))
			gpg_to.append( (enc, enc) )

		elif recipient_delimiter is not None and newenc in keys:
			# if the decomposed key matches the address directly
			emit_log("Adding encrypted and delimited recipient %s (%s)" %  (enc,newenc))
			gpg_to.append( (enc, newenc) )

                elif cfg.has_key('keymap') and cfg['keymap'].has_key(enc):
			# if the key is in our keymap and we can relate it back to a key we know of, we can encrypt to this address
			emit_log("Adding encrypted and mapped recipient %s (originally %s)" % (enc, cfg['keymap'][enc]))
                        gpg_to.append( (enc, cfg['keymap'][enc]) )

		elif recipient_delimiter is not None and cfg.has_key('keymap') and cfg['keymap'].has_key(newenc):
			# if the decomposed key matches something in our keymap
			emit_log("Adding encrypted, mapped, delimited recipient %s (originally %s)" % (enc, cfg['keymap'][newenc]))
			gpg_to.append( (enc, cfg['keymap'][newenc] ) )
			
		else:
			emit_log("Not adding encrypted recipient %s" % (enc))

	else:
		emit_log("Recipient %s isn't in our list of domains (%s), ignoring." % (enc,cfg['default']['domains']))

emit_log('unencrypted recipients to process: %s' % ', '.join(to_addrs))

for to in to_addrs:
	addr,domain = to.split('@')
	if recipient_delimiter is not None and recipient_delimiter in addr:
		# we have a delimiter!
		real_addr = addr.split(recipient_delimiter)[0] # only the left hand side
		newto = "%s@%s" % (real_addr,domain)
	else:
		newto = to

	if domain in cfg['default']['domains'].split(','):
		if to in keys:
			emit_log("Adding regular recipient %s" % (to))
			gpg_to.append( (to, to) )
		elif recipient_delimiter is not None and newto in keys:
			emit_log("Adding delimited regular recipient %s (originally %s)" % (to,newto))
			gpg_to.append( (to, newto) )
		elif cfg.has_key('keymap') and cfg['keymap'].has_key(to):
			emit_log("Adding mapped regular recipient %s (originally %s)" % (to,cfg['keymap'][to]))
			gpg_to.append( (to, cfg['keymap'][to]) )
		elif recipient_delimiter is not None and cfg.has_key('keymap') and cfg['keymap'].has_key(newto):
			emit_log("Adding delimited, mapped regular recipient %s (originally %s)" % (to,cfg['keymap'][newto]))
			gpg_to.append( (to, cfg['keymap'][newto]) )
		else:
			emit_log("No key found for recipient %s, adding to non-encrypted recipients." % (to))
			ungpg_to.append(to)

	else:
		emit_log("Recipient %s isn't in our list of domains (%s), ignoring." % (to,cfg['default']['domains']))

# if we have messages to encrypt to, send to them
#if gpg_to == list():
#	if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
#		raw_message['X-GPG-Mailgate'] = 'Not encrypted, public key not found'
##	send_msg( raw_message, to_addrs )
#	exit()

# if we have messages that aren't to be encrypted to, send to them as well
# first, log
# then, send
if ungpg_to != list():
	if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
		raw_message['X-GPG-Mailgate'] = 'Not encrypted, public key not found'
	emit_log("Sending unencrypted email to: %s\n" % ' '.join( map(lambda x: x[0], ungpg_to) ))
	send_msg( raw_message, ungpg_to )
else:
	emit_log("No unencrypted addresses to send to\n")

emit_log("Encrypting email to: %s\n" % ' '.join( map(lambda x: x[0], gpg_to) ))

if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
	raw_message['X-GPG-Mailgate'] = 'Encrypted by GPG Mailgate'

gpg_to_cmdline = list()
gpg_to_smtp = list()
for rcpt in gpg_to:
	gpg_to_smtp.append(rcpt[0])
	gpg_to_cmdline.extend(rcpt[1].split(','))

encrypted_payloads = encrypt_all_payloads( raw_message.get_payload(), gpg_to_cmdline )
raw_message.set_payload( encrypted_payloads )

send_msg( raw_message, gpg_to_smtp )
