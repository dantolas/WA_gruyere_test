# Kuta Samuel C4b
---
# Fixes
# XSS
- File Upload XSS
    - U can upload different types of files, including .html files. .html files can containt JS
    scripts, and that is a problem.
    - **FIX**:  Either check malicious content for every .html file a user posts, or host all user
    content on a seperate domain so that the .html file won't see any already present content
    in the user domain.

- Reflected XSS
    - JS Scripts injected through user input into the url.
    - **FIX**: Properly sanitize user input or auto-escape the output of a request. To fix this 
    issue in gruyere, a modifier can be added to the template that displays the error in 
    resources/error.gtl line 12 and adding the ':text' modifier
    - **AJAX**
    - 

- Stored XSS
    - JS scripts stored in content that is served to users. In gruyere the most obvious place is 
    snippets. Snippets are sanitized in sanitize.py, but there are issues.
    - **FIX** 
        - **Snippets**
        - Disabling onmouseover html property in all snippets by adding it to the dissalowed 
        properties tuple in sanitize.py line 84.

        - The dissalowed properties blacklist approach should be changed to a whitelist of the 
        allowed ones approach. A new list of **allowed_properties** should be made, and on line 
        99 where the chek is being performed it should be changed to if not in 
        **allowed_properties** replace it with blocked.

        - To fix the incorrect html syntax snippet, the HTML sanitization process should check 
        syntax and disallow wrong syntax snippets, or fix the syntax.

        - The entire **_SanitizeTag** function has many flaws, such as using case-sensitive blacklist
        of attributes instead of whitelisting the allowed ones, not properly checking html syntax
        and insufficient checking of 
        all html attributes. Best approach would be using a known and proven HTML sanitizer 
        should be used, for example the 
        [OWASP Java HTML Sanitizer](https://github.com/OWASP/java-html-sanitizer)
         or [bleach](https://github.com/mozilla/bleach) (bleach should be propably be used because
         it's written in python so integration should be easier)

         - **HTML Attribute**
         - Javascript can be inserted directly into html attributes such as color because of the 
         how the rendering engine renders the html.
         - To fix this the following function should be used in *gtl.py* instead of the 
         cgi.escape. :
             ```
             def _EscapeTextToHtml(var):
             """Escape HTML metacharacters.

              This function escapes characters that are dangerous to insert into
              HTML. It prevents XSS via quotes or script injected in attribute values.

              It is safer than cgi.escape, which escapes only <, >, & by default.
              cgi.escape can be told to escape double quotes, but it will never
              escape single quotes.
              """
              meta_chars = {
              '"': '&quot;',
              '\'': '&#39;',  # Not &apos;
              '&': '&amp;',
              '<': '&lt;',
              '>': '&gt;',
              }
              escaped_var = ""
              for i in var:
              if i in meta_chars:
              escaped_var = escaped_var + meta_chars[i]
              else:
              escaped_var = escaped_var + i
              return escaped_var
              ```
        - This still doesn't completely fix the issue, because of browser dynamic CSS expressions.
        To fix the issue for the color attribute for example, the following function should be used
        in order to sanitize the COLOR attribute in *gtl.py*:
            ```
            SAFE_COLOR_RE = re.compile(r"^#?[a-zA-Z0-9]*$")

            def _SanitizeColor(color):
              """Sanitizes a color, returning 'invalid' if it's invalid.

              A valid value is either the name of a color or # followed by the
              hex code for a color (like #FEFFFF). Returning an invalid value
              value allows a style sheet to specify a default value by writing
              'color:default; color:{{foo:color}}'.
              """

              if SAFE_COLOR_RE.match(color):
                return color
              return 'invalid'
            ```
        - This fixes the issue specifically for the color attribute, but similar fixes should be
        applied for for user-provided fonts, sizes, urls etc.

        - **AJAX**
        - The issue is caused by not properly escaping string quotation marks in the Ajax response.
        - To fix the issue, 2 fixes have to be made, one on the server side and one on the gruyere
        client side.
        - Server side fix: Properly escape all quotes when they are being rendered in a JSON 
        response. the should be escaped with these characters:  \x27 and \x22 instead of 
        &#27; and &quot; because those will not work when passed to JS, which is what the server does.
        - Browser fix : Never use javascript eval() function to check for valid JSON, instead use 
        the default javascript JSON Parser for more precision, error handling and overall better 
        everything.
# XSRF
- The issue with cross site request forgery exists because the browser sends all cookies it 
it currently has with every request. The server cannot distinguish between an intended user action,
and a malicious request because it only sees the request, not what caused it.

So if a user is logged in on a site and the browser owns the session cookie, any malicious JS from
anywhere could then try and send a malicious request from the user's browser, and it will go 
through because the browser has that session cookie.
- **Delete snippet**
- A specific example of this is that a we can delete a user's snippet after they log in just by
for example changing our own profile picture URL to this malicious request. This information is 
displayed to the end user after he logs in, and the browser tries to request the image of our 
profile by sending the request that's specified in the img src attribute.
- **FIX**
- First we should change the /deletesnippet API endpoint to only work on POST requests, that 
eliminates all get request to /deletesnippet from working.
- Then also send a unique unpredictable authorization token along with each POST request 
initiated by the user, such as the session cookie hashed with current timestamp. The server can
then eliminate all POST requests to the url it recieves by checkign the validity of this token.
- However, if an attacked got hold of a copy of this token, he could then use it until this token
expired. To eliminate this issue, the request should also include the specific action that 
triggered it, so that the token can only be used for that action.
- We can then generate a token and verify it with these functions for example, that are executed
on specific submit or send actions:
```
def _GenerateXsrfToken(self, cookie,action):
  """Generates a timestamp and XSRF token for all state changing actions."""

  timestamp = time.time()
  return timestamp + "|" + (str(hash(cookie_secret + cookie + timestamp + action)))

def _VerifyXsrfToken(self, cookie, action_token):
  """Verifies an XSRF token included in a request."""

  # First, make sure that the token isn't more than a day old.
  (action_time,action, action_hash) = action_token.split("|", 1)
  now = time.time()
  if now - 86400 > float(action_time):
    return False

  # Second, regenerate it and check that it matches the user supplied value
  hash_to_verify = str(hash(cookie_secret + cookie + action_time + action)
  return action_hash == hash_to_verify
```

