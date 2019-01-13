# Copyright 2019 - Thomas T. Jarløv

import db_sqlite, os, parsecfg, strutils, logging

import ../code/password_utils

proc generateDB*() =
  echo "Generating database"

  # Load the connection details
  let
    dict = loadConfig("config/config.cfg")
    db_user = dict.getSectionValue("Database","user")
    db_pass = dict.getSectionValue("Database","pass")
    db_name = dict.getSectionValue("Database","name")
    db_host = dict.getSectionValue("Database","host")
    db_folder = dict.getSectionValue("Database","folder")
    dbexists = if fileExists(db_host): true else: false

  if dbexists:
    echo " - Database already exists. Inserting tables if they do not exist."

  # Creating database folder if it doesn't exist
  discard existsOrCreateDir(db_folder)

  # Open DB
  echo " - Opening database"
  var db = open(connection=db_host, user=db_user, password=db_pass, database=db_name)

  # Person table contains information about the
  # registrered users
  if not db.tryExec(sql("""
  create table if not exists person(
    id integer primary key,
    name varchar(60) not null,
    password varchar(300) not null,
    email varchar(254) not null,
    creation timestamp not null default (STRFTIME('%s', 'now')),
    modified timestamp not null default (STRFTIME('%s', 'now')),
    salt varbin(128) not null,
    status varchar(30) not null,
    timezone VARCHAR(100),
    secretUrl VARCHAR(250),
    lastOnline timestamp not null default (STRFTIME('%s', 'now'))
  );""")):
    echo " - Database: person table already exists"

  # Session table contains information about the users
  # cookie ID, IP and last visit
  if not db.tryExec(sql("""
  create table if not exists session(
    id integer primary key,
    ip inet not null,
    key varchar(300) not null,
    userid integer not null,
    lastModified timestamp not null default (STRFTIME('%s', 'now')),
    foreign key (userid) references person(id)
  );""")):
    echo " - Database: session table already exists"


proc createAdminUser*(db: DbConn, args: seq[string]) =
  ## Create new admin user

  var iName = ""
  var iEmail = ""
  var iPwd = ""

  # Loop through all the arguments and get the args
  # containing the user information
  for arg in args:
    if arg.substr(0, 1) == "u:":
      iName = arg.substr(2, arg.len())
    elif arg.substr(0, 1) == "p:":
      iPwd = arg.substr(2, arg.len())
    elif arg.substr(0, 1) == "e:":
      iEmail = arg.substr(2, arg.len())

  # If the name, password or emails does not exists
  # return error
  if iName == "" or iPwd == "" or iEmail == "":
    error("Missing either name, password or email to create the Admin user.")

  # Generate the password using a salt and hashing.
  # Read more about hashing and salting here:
  #   - https://crackstation.net/hashing-security.htm
  #   - https://en.wikipedia.org/wiki/Salt_(cryptography)
  let salt = makeSalt()
  let password = makePassword(iPwd, salt)

  # Insert user into database
  if insertID(db, sql"INSERT INTO person (name, email, password, salt, status) VALUES (?, ?, ?, ?, ?)", $iName, $iEmail, password, salt, "Admin") > 0:
    echo "Admin user added"
  else:
    error("Something went wrong")

  info("Admin added.")