# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: evm.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='evm.proto',
  package='evm',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\tevm.proto\x12\x03\x65vm\"\x18\n\x06Status\x12\x0e\n\x06option\x18\x01 \x01(\r\"$\n\x06Source\x12\x0c\n\x04text\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\"\x14\n\x04Json\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\t\"\x1a\n\x07\x41\x64\x64ress\x12\x0f\n\x07\x61\x64\x64ress\x18\x01 \x01(\t\"Y\n\nSendTxData\x12\x10\n\x08\x66romAddr\x18\x01 \x01(\t\x12\x0e\n\x06toAddr\x18\x02 \x01(\t\x12\r\n\x05value\x18\x03 \x01(\t\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\t\x12\x0c\n\x04opts\x18\x05 \x01(\r2\xcd\x01\n\x03\x45VM\x12%\n\x05Reset\x12\x0b.evm.Status\x1a\x0b.evm.Status\"\x00\x30\x01\x12)\n\x0bGetAccounts\x12\x0b.evm.Status\x1a\t.evm.Json\"\x00\x30\x01\x12#\n\x07\x43ompile\x12\x0b.evm.Source\x1a\t.evm.Json\"\x00\x12%\n\x06\x44\x65ploy\x12\t.evm.Json\x1a\x0c.evm.Address\"\x00\x30\x01\x12(\n\x06SendTx\x12\x0f.evm.SendTxData\x1a\t.evm.Json\"\x00\x30\x01\x62\x06proto3')
)




_STATUS = _descriptor.Descriptor(
  name='Status',
  full_name='evm.Status',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='option', full_name='evm.Status.option', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=18,
  serialized_end=42,
)


_SOURCE = _descriptor.Descriptor(
  name='Source',
  full_name='evm.Source',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='text', full_name='evm.Source.text', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='name', full_name='evm.Source.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=44,
  serialized_end=80,
)


_JSON = _descriptor.Descriptor(
  name='Json',
  full_name='evm.Json',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='data', full_name='evm.Json.data', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=82,
  serialized_end=102,
)


_ADDRESS = _descriptor.Descriptor(
  name='Address',
  full_name='evm.Address',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='address', full_name='evm.Address.address', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=104,
  serialized_end=130,
)


_SENDTXDATA = _descriptor.Descriptor(
  name='SendTxData',
  full_name='evm.SendTxData',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='fromAddr', full_name='evm.SendTxData.fromAddr', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='toAddr', full_name='evm.SendTxData.toAddr', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='evm.SendTxData.value', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='data', full_name='evm.SendTxData.data', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='opts', full_name='evm.SendTxData.opts', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=132,
  serialized_end=221,
)

DESCRIPTOR.message_types_by_name['Status'] = _STATUS
DESCRIPTOR.message_types_by_name['Source'] = _SOURCE
DESCRIPTOR.message_types_by_name['Json'] = _JSON
DESCRIPTOR.message_types_by_name['Address'] = _ADDRESS
DESCRIPTOR.message_types_by_name['SendTxData'] = _SENDTXDATA
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Status = _reflection.GeneratedProtocolMessageType('Status', (_message.Message,), dict(
  DESCRIPTOR = _STATUS,
  __module__ = 'evm_pb2'
  # @@protoc_insertion_point(class_scope:evm.Status)
  ))
_sym_db.RegisterMessage(Status)

Source = _reflection.GeneratedProtocolMessageType('Source', (_message.Message,), dict(
  DESCRIPTOR = _SOURCE,
  __module__ = 'evm_pb2'
  # @@protoc_insertion_point(class_scope:evm.Source)
  ))
_sym_db.RegisterMessage(Source)

Json = _reflection.GeneratedProtocolMessageType('Json', (_message.Message,), dict(
  DESCRIPTOR = _JSON,
  __module__ = 'evm_pb2'
  # @@protoc_insertion_point(class_scope:evm.Json)
  ))
_sym_db.RegisterMessage(Json)

Address = _reflection.GeneratedProtocolMessageType('Address', (_message.Message,), dict(
  DESCRIPTOR = _ADDRESS,
  __module__ = 'evm_pb2'
  # @@protoc_insertion_point(class_scope:evm.Address)
  ))
_sym_db.RegisterMessage(Address)

SendTxData = _reflection.GeneratedProtocolMessageType('SendTxData', (_message.Message,), dict(
  DESCRIPTOR = _SENDTXDATA,
  __module__ = 'evm_pb2'
  # @@protoc_insertion_point(class_scope:evm.SendTxData)
  ))
_sym_db.RegisterMessage(SendTxData)



_EVM = _descriptor.ServiceDescriptor(
  name='EVM',
  full_name='evm.EVM',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=224,
  serialized_end=429,
  methods=[
  _descriptor.MethodDescriptor(
    name='Reset',
    full_name='evm.EVM.Reset',
    index=0,
    containing_service=None,
    input_type=_STATUS,
    output_type=_STATUS,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='GetAccounts',
    full_name='evm.EVM.GetAccounts',
    index=1,
    containing_service=None,
    input_type=_STATUS,
    output_type=_JSON,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='Compile',
    full_name='evm.EVM.Compile',
    index=2,
    containing_service=None,
    input_type=_SOURCE,
    output_type=_JSON,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='Deploy',
    full_name='evm.EVM.Deploy',
    index=3,
    containing_service=None,
    input_type=_JSON,
    output_type=_ADDRESS,
    serialized_options=None,
  ),
  _descriptor.MethodDescriptor(
    name='SendTx',
    full_name='evm.EVM.SendTx',
    index=4,
    containing_service=None,
    input_type=_SENDTXDATA,
    output_type=_JSON,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_EVM)

DESCRIPTOR.services_by_name['EVM'] = _EVM

# @@protoc_insertion_point(module_scope)
