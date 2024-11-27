import hashlib
import json
import sqlite3
import logging
from mitmproxy.http import HTTPFlow


class FlowDBWriter:
    conn: sqlite3.Connection
    cursor: sqlite3.Cursor
    logger: logging.Logger

    def __init__(self, db_path):
        try:
            self.logger = logging.getLogger(__name__)
            self.conn = sqlite3.connect(db_path)
            self.cursor = self.conn.cursor()
            self.logger.info("Connected to database: {}".format(db_path))
            self.create_table()
        except Exception as err:
            raise err

    def create_table(self):
        try:
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS flowData (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Method TEXT,
            URI TEXT,
            HttpVersion TEXT,
            ReqHeaders TEXT,
            ReqBody TEXT,
            ReqHeadersMd5 TEXT,
            ReqBodyMd5 TEXT,
            StatusCode INTEGER,
            StatusMsg TEXT,
            ResHeaders TEXT,
            ResBody TEXT)''')
            self.conn.commit()
        except sqlite3.Error as err:
            raise Exception("Error creating table: {}".format(err))

    def add_flow(self, flow: HTTPFlow):
        try:
            dictHeader = {}
            for key, value in flow.request.headers.items():
                dictHeader[key] = value
            headerStr = json.dumps(dictHeader)
            headerMD5 = hashlib.md5(headerStr.encode('utf-8')).hexdigest()

            bodyStr = ""
            bodyMD5 = ""
            if len(flow.request.content)>0:
                bodyStr = flow.request.content.decode('utf-8')
                bodyMD5 = hashlib.md5(flow.request.content).hexdigest()


            dictHeader = {}
            for key, value in flow.response.headers.items():
                dictHeader = {}[key] = value
            resHeaderStr = json.dumps(dictHeader)

            resBodyStr =""
            if len(flow.response.content)>0:
                resBodyStr =  flow.response.content.decode('utf-8')

            self.cursor.execute('''INSERT INTO flowData (
                Method, 
                URI, 
                HttpVersion, 
                ReqHeaders, 
                ReqBody, 
                ReqHeadersMd5, 
                ReqBodyMd5, 
                StatusCode, 
                StatusMsg, 
                ResHeaders, 
                ResBody
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                flow.request.method,        # Method
                flow.request.url,           # URI
                flow.request.http_version,  # HttpVersion
                headerStr,                  # ReqHeaders
                bodyStr,                    # ReqBody
                headerMD5,                  # ReqHeadersMd5
                bodyMD5,                    # ReqBodyMd5
                flow.response.status_code,  # StatusCode
                flow.response.reason,       # StatusMsg
                resHeaderStr,               # ResHeaders
                resBodyStr                  # ResBody
            ))
            self.conn.commit()
        except Exception as err:
            raise err

    def closeCon(self):
        self.conn.close()
