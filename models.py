from os import path, remove

from peewee import *

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
    start_delay = IntegerField()
    start_retry_count = IntegerField()
    sub_domain = CharField()
    
    # Some containers perform initial actions on first start such as 
    # create a db. If start_on_create is set to true the container
    # is started so that the action can be performed against the 
    # container layer
    start_on_create = BooleanField()

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
