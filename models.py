from peewee import *
from os import path, remove

FILE_NAME = 'containers.db'

db = SqliteDatabase(FILE_NAME)


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
    number = IntegerField()
    protocol = IntegerField()


class FirewallRule(BaseModel):
    id = PrimaryKeyField(null=False)
    src = CharField(null=True)
    dst = CharField(null=True)
    protocol = CharField()
    dport = CharField(null=True)
    sport = CharField(null=True)
    table = CharField()
    chain = CharField()
    queue_num = IntegerField()


def setup_database():
    db.connect()

    if not Container.table_exists():
        Container.create_table(True)
    if not Port.table_exists():
        Port.create_table(True)
    if not FirewallRule.table_exists():
        FirewallRule.create_table()


def close_database():
    db.close()
