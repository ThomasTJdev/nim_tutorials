# Copyright 2019 - Thomas T. Jarløv

import db_sqlite # SQLite
import jester    # Our webserver
import logging   # Logging utils
import os        # Used to get arguments
import parsecfg  # Parse CFG (config) files
import strutils  # Basic functions
import times     # Time and date
import uri       # We need to encode urls: encodeUrl()
import code/database_utils # Utils used in the database
import code/password_utils # Our file with password utils


# First we'll load config files
let dict = loadConfig("config/config.cfg")


# Now we get the values and assign them.
# We do not need to change them later, therefore
# we'll use `let`
let db_user   = dict.getSectionValue("Database", "user")
let db_pass   = dict.getSectionValue("Database", "pass")
let db_name   = dict.getSectionValue("Database", "name")
let db_host   = dict.getSectionValue("Database", "host")

let mainURL   = dict.getSectionValue("Server", "url")
let mainPort  = parseInt dict.getSectionValue("Server", "port")
let mainWebsite = dict.getSectionValue("Server", "website")


# Database var
var db: DbConn


# Jester setting server settings
settings:
  port = Port(mainPort)
  bindAddr = mainURL


# Setup user data
type
  TData* = ref object of RootObj
    loggedIn*: bool
    userid, username*, userpass*, email*: string
    req*: Request


proc init(c: var TData) =
  ## Empty out user session data
  c.userpass = ""
  c.username = ""
  c.userid   = ""
  c.loggedIn = false


func loggedIn(c: TData): bool =
  ## Check if user is logged in by verifying that c.username exists
  c.username.len > 0


proc checkLoggedIn(c: var TData) =
  ## Check if user is logged in

  # Get the users cookie named `sid`. If it does not exist, return
  if not c.req.cookies.hasKey("sid"): return

  # Assign cookie to `let sid`
  let sid = c.req.cookies["sid"]

  # Update the value lastModified for the user in the
  # table session where the sid and IP match. If there's
  # any results (above 0) assign values
  if execAffectedRows(db, sql("UPDATE session SET lastModified = " & $toInt(epochTime()) & " " & "WHERE ip = ? AND key = ?"), c.req.ip, sid) > 0:

    # Get user data based on userID from session table
    # Assign values to user details - `c`
    c.userid = getValue(db, sql"SELECT userid FROM session WHERE ip = ? AND key = ?", c.req.ip, sid)

    # Get user data based on userID from person table
    let row = getRow(db, sql"SELECT name, email, status FROM person WHERE id = ?", c.userid)

    # Assign user data
    c.username  = row[0]
    c.email     = toLowerAscii(row[1])

    # Update our session table with info about activity
    discard tryExec(db, sql"UPDATE person SET lastOnline = ? WHERE id = ?", toInt(epochTime()), c.userid)

  else:
    # If the user is not found in the session table
    c.loggedIn = false


proc login(c: var TData, email, pass: string): tuple[b: bool, s: string] =
  ## User login

  # We have predefined query
  const query = sql"SELECT id, name, password, email, salt, status FROM person WHERE email = ?"

  # If the email or pass passed in the proc's parameters is empty, fail
  if email.len == 0 or pass.len == 0:
    return (false, "Missing password or username")

  # We'll use fastRows for a quick query.
  # Notice that the email is set to lower ascii
  # to avoid problems if the user has any
  # capitalized letters.
  for row in fastRows(db, query, toLowerAscii(email)):

    # Now our password library is going to work. It'll
    # check the password against the hashed password
    # and salt.
    if row[2] == makePassword(pass, row[4], row[2]):
      # Assign the values
      c.userid   = row[0]
      c.username = row[1]
      c.userpass = row[2]
      c.email    = toLowerAscii(row[3])

      # Generate session key and save it
      let key = makeSessionKey()
      exec(db, sql"INSERT INTO session (ip, key, userid) VALUES (?, ?, ?)", c.req.ip, key, row[0])

      info("Login successful")
      return (true, key)

  info("Login failed")
  return (false, "Login failed")


proc logout(c: var TData) =
  ## Logout

  c.username = ""
  c.userpass = ""
  const query = sql"DELETE FROM session WHERE ip = ? AND key = ?"
  exec(db, query, c.req.ip, c.req.cookies["sid"])


# Do the check inside our routes
template createTFD() =
  ## Check if logged in and assign data to user

  # Assign the c to TDATA
  var c {.inject.}: TData
  # New instance of c
  new(c)
  # Set standard values
  init(c)
  # Get users request
  c.req = request
  # Check for cookies (we need the cookie named sid)
  if cookies(request).len > 0:
    # Check if user is logged in
    checkLoggedIn(c)
  # Use the func()
  c.loggedIn = loggedIn(c)


# isMainModule
when isMainModule:
  echo "Nim Web is now running: " & $now()

  # Generate DB if newdb is in the arguments
  # or if the database does not exists
  if "newdb" in commandLineParams() or not fileExists(db_host):
    generateDB()
    quit()

  # Connect to DB
  try:
    # We are using the values which we assigned earlier
    db = open(connection=db_host, user=db_user, password=db_pass, database=db_name)
    info("Connection to DB is established.")
  except:
    fatal("Connection to DB could not be established.")
    sleep(5_000)
    quit()

  # Add an admin user if newuser is in the args
  if "newuser" in commandLineParams():
    createAdminUser(db, commandLineParams())
    quit()


# Include template files
include "tmpl/main.tmpl"
include "tmpl/user.tmpl"


# Setup routes (URL's)
routes:
  get "/":
    createTFD()
    resp genMain(c)

  get "/secret":
    createTFD()
    if c.loggedIn:
      resp genSecret(c)

  get "/login":
    createTFD()
    resp genLogin(c, @"msg")

  post "/dologin":
    createTFD()

    let (loginB, loginS) = login(c, replace(toLowerAscii(@"email"), " ", ""), replace(@"password", " ", ""))
    if loginB:
      jester.setCookie("sid", loginS, daysForward(7))
      redirect("/secret")
    else:
      redirect("/login?msg=" & encodeUrl(loginS))

  get "/logout":
    createTFD()
    logout(c)
    redirect("/")
