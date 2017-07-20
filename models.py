import os
from peewee import *

db = SqliteDatabase("containers.db")

class BaseModel(Model):
    class Meta:
        database = db

class Container(BaseModel):
    id = PrimaryKeyField(null=False)
    container_id = CharField()
    name = CharField()
    ip = CharField()
    mac = CharField()


class Port(BaseModel):
    id = PrimaryKeyField(null=False)
    container = ForeignKeyField(Container, related_name="ports")
    value = IntegerField()

os.remove('containers.db')
db.connect()
Container.create_table()
Port.create_table()