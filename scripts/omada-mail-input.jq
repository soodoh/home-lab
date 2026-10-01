# Desired SMTP input, not a controller API payload. Never emit its values.
def exact_keys($wanted):
  type == "object" and (keys == ($wanted | sort));
def single_line:
  type == "string" and length > 0 and (test("[\r\n\u0000]") | not);
def email:
  single_line and test("^[^@[:space:]<>]+@[^@[:space:]<>]+\\.[^@[:space:]<>]+$");
try (
  exact_keys(["schema_version", "smtp", "recipients"]) and
  (.schema_version == 1) and
  (.smtp | exact_keys(["host", "port", "security", "username", "password", "sender"])) and
  (.smtp.host | single_line and test("^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")) and
  (.smtp.port | type == "number" and floor == . and . >= 1 and . <= 65535) and
  (.smtp.security | . == "starttls" or . == "tls") and
  (.smtp.username | single_line) and
  (.smtp.password | single_line) and
  (.smtp.sender | email) and
  (.recipients | type == "array" and length > 0 and all(.[]; email) and (unique | length) == length) and
  # Proton submission requires the token's paired address as sender.
  (if .smtp.host == "smtp.protonmail.ch" then
    .smtp.port == 587 and .smtp.security == "starttls" and .smtp.sender == .smtp.username
   else true end)
) catch false
