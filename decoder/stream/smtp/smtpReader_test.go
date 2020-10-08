/*
* NETCAP - Traffic Analysis Framework
* Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package smtp

// 220 smtp-gw11.han.skanova.net ESMTP Service ready
// HELO passwordnedxp
// 250 smtp-gw11.han.skanova.net
// MAIL FROM: <ned.pwned.se@gmx.com>
// 250 MAIL FROM:<ned.pwned.se@gmx.com> OK
// RCPT TO: <homer.pwned.se@gmx.com>
// 250 RCPT TO:<homer.pwned.se@gmx.com> OK
// DATA
// 354 Start mail input; end with <CRLF>.<CRLF>
// Message-ID: <8501ED1263D742DFB6B601A139AA38EC@passwordnedxp>
// From: "Password Ned" <ned.pwned.se@gmx.com>
// To: <homer.pwned.se@gmx.com>
// Subject: I'm on-diddly-line now!
// Date: Mon, 9 Mar 2015 11:03:58 +0100
// Organization: pwned.se
// MIME-Version: 1.0
// Content-Type: multipart/alternative;
// boundary="----=_NextPart_000_0006_01D05A58.BE14CB00"
// X-Priority: 3
// X-MSMail-Priority: Normal
// X-Mailer: Microsoft Outlook Express 6.00.2900.5512
// X-MimeOLE: Produced By Microsoft MimeOLE V6.00.2900.5512
//
// This is a multi-part message in MIME format.
//
// ------=_NextPart_000_0006_01D05A58.BE14CB00
// Content-Type: text/plain;
// charset="iso-8859-1"
// Content-Transfer-Encoding: quoted-printable
//
// Hello Neighborino,
//
// I've now got a e-mail addres.
//
// Good-diddly-bye!
// ------=_NextPart_000_0006_01D05A58.BE14CB00
// Content-Type: text/html;
// charset="iso-8859-1"
// Content-Transfer-Encoding: quoted-printable
//
// <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
// <HTML><HEAD>
// <META content=3D"text/html; charset=3Diso-8859-1" =
// http-equiv=3DContent-Type>
// <META name=3DGENERATOR content=3D"MSHTML 8.00.6001.18702">
// <STYLE></STYLE>
// </HEAD>
// <BODY bgColor=3D#ffffff>
// <DIV><FONT size=3D2 face=3DArial>Hello Neighborino,</FONT></DIV>
// <DIV><FONT size=3D2 face=3DArial></FONT>&nbsp;</DIV>
// <DIV><FONT size=3D2 face=3DArial>I've now got a e-mail =
// addres.</FONT></DIV>
// <DIV><FONT size=3D2 face=3DArial></FONT>&nbsp;</DIV>
// <DIV><FONT size=3D2 =
// face=3DArial>Good-diddly-bye!</FONT></DIV></BODY></HTML>
//
// ------=_NextPart_000_0006_01D05A58.BE14CB00--
//
// .
// 250 <54E6F832004A05C2> Mail accepted
// QUIT
// 221 smtp-gw11.han.skanova.net QUIT
