# web

The web app: paste an email or URL, or pick a `.eml` file, and see the
report with each finding's evidence highlighted. React, TypeScript (strict)
and Vite, with ESLint and Vitest. Built in the "Web app" milestone.

A picked `.eml` file is read in the browser and sent to the engine as the
raw request body (`Content-Type: message/rfc822`), so it is never uploaded
as multipart and never written to disk on the server.
