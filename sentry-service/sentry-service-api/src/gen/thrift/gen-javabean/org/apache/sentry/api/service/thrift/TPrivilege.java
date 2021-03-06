/**
 * Autogenerated by Thrift Compiler (0.9.3)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package org.apache.sentry.api.service.thrift;

import org.apache.thrift.scheme.IScheme;
import org.apache.thrift.scheme.SchemeFactory;
import org.apache.thrift.scheme.StandardScheme;

import org.apache.thrift.scheme.TupleScheme;
import org.apache.thrift.protocol.TTupleProtocol;
import org.apache.thrift.protocol.TProtocolException;
import org.apache.thrift.EncodingUtils;
import org.apache.thrift.TException;
import org.apache.thrift.async.AsyncMethodCallback;
import org.apache.thrift.server.AbstractNonblockingServer.*;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.EnumMap;
import java.util.Set;
import java.util.HashSet;
import java.util.EnumSet;
import java.util.Collections;
import java.util.BitSet;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.annotation.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings({"cast", "rawtypes", "serial", "unchecked"})
@Generated(value = "Autogenerated by Thrift Compiler (0.9.3)")
public class TPrivilege implements org.apache.thrift.TBase<TPrivilege, TPrivilege._Fields>, java.io.Serializable, Cloneable, Comparable<TPrivilege> {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("TPrivilege");

  private static final org.apache.thrift.protocol.TField ACTION_FIELD_DESC = new org.apache.thrift.protocol.TField("action", org.apache.thrift.protocol.TType.STRING, (short)1);
  private static final org.apache.thrift.protocol.TField CREATE_TIME_FIELD_DESC = new org.apache.thrift.protocol.TField("createTime", org.apache.thrift.protocol.TType.I64, (short)2);
  private static final org.apache.thrift.protocol.TField GRANT_OPTION_FIELD_DESC = new org.apache.thrift.protocol.TField("grantOption", org.apache.thrift.protocol.TType.I32, (short)3);

  private static final Map<Class<? extends IScheme>, SchemeFactory> schemes = new HashMap<Class<? extends IScheme>, SchemeFactory>();
  static {
    schemes.put(StandardScheme.class, new TPrivilegeStandardSchemeFactory());
    schemes.put(TupleScheme.class, new TPrivilegeTupleSchemeFactory());
  }

  private String action; // required
  private long createTime; // optional
  private TSentryGrantOption grantOption; // optional

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    ACTION((short)1, "action"),
    CREATE_TIME((short)2, "createTime"),
    /**
     * 
     * @see TSentryGrantOption
     */
    GRANT_OPTION((short)3, "grantOption");

    private static final Map<String, _Fields> byName = new HashMap<String, _Fields>();

    static {
      for (_Fields field : EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    public static _Fields findByThriftId(int fieldId) {
      switch(fieldId) {
        case 1: // ACTION
          return ACTION;
        case 2: // CREATE_TIME
          return CREATE_TIME;
        case 3: // GRANT_OPTION
          return GRANT_OPTION;
        default:
          return null;
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, throwing an exception
     * if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null) throw new IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }

    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    public static _Fields findByName(String name) {
      return byName.get(name);
    }

    private final short _thriftId;
    private final String _fieldName;

    _Fields(short thriftId, String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }

    public short getThriftFieldId() {
      return _thriftId;
    }

    public String getFieldName() {
      return _fieldName;
    }
  }

  // isset id assignments
  private static final int __CREATETIME_ISSET_ID = 0;
  private byte __isset_bitfield = 0;
  private static final _Fields optionals[] = {_Fields.CREATE_TIME,_Fields.GRANT_OPTION};
  public static final Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.ACTION, new org.apache.thrift.meta_data.FieldMetaData("action", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.STRING)));
    tmpMap.put(_Fields.CREATE_TIME, new org.apache.thrift.meta_data.FieldMetaData("createTime", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I64)));
    tmpMap.put(_Fields.GRANT_OPTION, new org.apache.thrift.meta_data.FieldMetaData("grantOption", org.apache.thrift.TFieldRequirementType.OPTIONAL, 
        new org.apache.thrift.meta_data.EnumMetaData(org.apache.thrift.protocol.TType.ENUM, TSentryGrantOption.class)));
    metaDataMap = Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(TPrivilege.class, metaDataMap);
  }

  public TPrivilege() {
    this.action = "";

    this.grantOption = org.apache.sentry.api.service.thrift.TSentryGrantOption.FALSE;

  }

  public TPrivilege(
    String action)
  {
    this();
    this.action = action;
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public TPrivilege(TPrivilege other) {
    __isset_bitfield = other.__isset_bitfield;
    if (other.isSetAction()) {
      this.action = other.action;
    }
    this.createTime = other.createTime;
    if (other.isSetGrantOption()) {
      this.grantOption = other.grantOption;
    }
  }

  public TPrivilege deepCopy() {
    return new TPrivilege(this);
  }

  @Override
  public void clear() {
    this.action = "";

    setCreateTimeIsSet(false);
    this.createTime = 0;
    this.grantOption = org.apache.sentry.api.service.thrift.TSentryGrantOption.FALSE;

  }

  public String getAction() {
    return this.action;
  }

  public void setAction(String action) {
    this.action = action;
  }

  public void unsetAction() {
    this.action = null;
  }

  /** Returns true if field action is set (has been assigned a value) and false otherwise */
  public boolean isSetAction() {
    return this.action != null;
  }

  public void setActionIsSet(boolean value) {
    if (!value) {
      this.action = null;
    }
  }

  public long getCreateTime() {
    return this.createTime;
  }

  public void setCreateTime(long createTime) {
    this.createTime = createTime;
    setCreateTimeIsSet(true);
  }

  public void unsetCreateTime() {
    __isset_bitfield = EncodingUtils.clearBit(__isset_bitfield, __CREATETIME_ISSET_ID);
  }

  /** Returns true if field createTime is set (has been assigned a value) and false otherwise */
  public boolean isSetCreateTime() {
    return EncodingUtils.testBit(__isset_bitfield, __CREATETIME_ISSET_ID);
  }

  public void setCreateTimeIsSet(boolean value) {
    __isset_bitfield = EncodingUtils.setBit(__isset_bitfield, __CREATETIME_ISSET_ID, value);
  }

  /**
   * 
   * @see TSentryGrantOption
   */
  public TSentryGrantOption getGrantOption() {
    return this.grantOption;
  }

  /**
   * 
   * @see TSentryGrantOption
   */
  public void setGrantOption(TSentryGrantOption grantOption) {
    this.grantOption = grantOption;
  }

  public void unsetGrantOption() {
    this.grantOption = null;
  }

  /** Returns true if field grantOption is set (has been assigned a value) and false otherwise */
  public boolean isSetGrantOption() {
    return this.grantOption != null;
  }

  public void setGrantOptionIsSet(boolean value) {
    if (!value) {
      this.grantOption = null;
    }
  }

  public void setFieldValue(_Fields field, Object value) {
    switch (field) {
    case ACTION:
      if (value == null) {
        unsetAction();
      } else {
        setAction((String)value);
      }
      break;

    case CREATE_TIME:
      if (value == null) {
        unsetCreateTime();
      } else {
        setCreateTime((Long)value);
      }
      break;

    case GRANT_OPTION:
      if (value == null) {
        unsetGrantOption();
      } else {
        setGrantOption((TSentryGrantOption)value);
      }
      break;

    }
  }

  public Object getFieldValue(_Fields field) {
    switch (field) {
    case ACTION:
      return getAction();

    case CREATE_TIME:
      return getCreateTime();

    case GRANT_OPTION:
      return getGrantOption();

    }
    throw new IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new IllegalArgumentException();
    }

    switch (field) {
    case ACTION:
      return isSetAction();
    case CREATE_TIME:
      return isSetCreateTime();
    case GRANT_OPTION:
      return isSetGrantOption();
    }
    throw new IllegalStateException();
  }

  @Override
  public boolean equals(Object that) {
    if (that == null)
      return false;
    if (that instanceof TPrivilege)
      return this.equals((TPrivilege)that);
    return false;
  }

  public boolean equals(TPrivilege that) {
    if (that == null)
      return false;

    boolean this_present_action = true && this.isSetAction();
    boolean that_present_action = true && that.isSetAction();
    if (this_present_action || that_present_action) {
      if (!(this_present_action && that_present_action))
        return false;
      if (!this.action.equals(that.action))
        return false;
    }

    boolean this_present_createTime = true && this.isSetCreateTime();
    boolean that_present_createTime = true && that.isSetCreateTime();
    if (this_present_createTime || that_present_createTime) {
      if (!(this_present_createTime && that_present_createTime))
        return false;
      if (this.createTime != that.createTime)
        return false;
    }

    boolean this_present_grantOption = true && this.isSetGrantOption();
    boolean that_present_grantOption = true && that.isSetGrantOption();
    if (this_present_grantOption || that_present_grantOption) {
      if (!(this_present_grantOption && that_present_grantOption))
        return false;
      if (!this.grantOption.equals(that.grantOption))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    List<Object> list = new ArrayList<Object>();

    boolean present_action = true && (isSetAction());
    list.add(present_action);
    if (present_action)
      list.add(action);

    boolean present_createTime = true && (isSetCreateTime());
    list.add(present_createTime);
    if (present_createTime)
      list.add(createTime);

    boolean present_grantOption = true && (isSetGrantOption());
    list.add(present_grantOption);
    if (present_grantOption)
      list.add(grantOption.getValue());

    return list.hashCode();
  }

  @Override
  public int compareTo(TPrivilege other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;

    lastComparison = Boolean.valueOf(isSetAction()).compareTo(other.isSetAction());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetAction()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.action, other.action);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = Boolean.valueOf(isSetCreateTime()).compareTo(other.isSetCreateTime());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetCreateTime()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.createTime, other.createTime);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = Boolean.valueOf(isSetGrantOption()).compareTo(other.isSetGrantOption());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetGrantOption()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.grantOption, other.grantOption);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    return 0;
  }

  public _Fields fieldForId(int fieldId) {
    return _Fields.findByThriftId(fieldId);
  }

  public void read(org.apache.thrift.protocol.TProtocol iprot) throws org.apache.thrift.TException {
    schemes.get(iprot.getScheme()).getScheme().read(iprot, this);
  }

  public void write(org.apache.thrift.protocol.TProtocol oprot) throws org.apache.thrift.TException {
    schemes.get(oprot.getScheme()).getScheme().write(oprot, this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("TPrivilege(");
    boolean first = true;

    sb.append("action:");
    if (this.action == null) {
      sb.append("null");
    } else {
      sb.append(this.action);
    }
    first = false;
    if (isSetCreateTime()) {
      if (!first) sb.append(", ");
      sb.append("createTime:");
      sb.append(this.createTime);
      first = false;
    }
    if (isSetGrantOption()) {
      if (!first) sb.append(", ");
      sb.append("grantOption:");
      if (this.grantOption == null) {
        sb.append("null");
      } else {
        sb.append(this.grantOption);
      }
      first = false;
    }
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    if (!isSetAction()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'action' is unset! Struct:" + toString());
    }

    // check for sub-struct validity
  }

  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    try {
      write(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(out)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, ClassNotFoundException {
    try {
      // it doesn't seem like you should have to do this, but java serialization is wacky, and doesn't call the default constructor.
      __isset_bitfield = 0;
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class TPrivilegeStandardSchemeFactory implements SchemeFactory {
    public TPrivilegeStandardScheme getScheme() {
      return new TPrivilegeStandardScheme();
    }
  }

  private static class TPrivilegeStandardScheme extends StandardScheme<TPrivilege> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, TPrivilege struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // ACTION
            if (schemeField.type == org.apache.thrift.protocol.TType.STRING) {
              struct.action = iprot.readString();
              struct.setActionIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // CREATE_TIME
            if (schemeField.type == org.apache.thrift.protocol.TType.I64) {
              struct.createTime = iprot.readI64();
              struct.setCreateTimeIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 3: // GRANT_OPTION
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.grantOption = org.apache.sentry.api.service.thrift.TSentryGrantOption.findByValue(iprot.readI32());
              struct.setGrantOptionIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          default:
            org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
        }
        iprot.readFieldEnd();
      }
      iprot.readStructEnd();
      struct.validate();
    }

    public void write(org.apache.thrift.protocol.TProtocol oprot, TPrivilege struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      if (struct.action != null) {
        oprot.writeFieldBegin(ACTION_FIELD_DESC);
        oprot.writeString(struct.action);
        oprot.writeFieldEnd();
      }
      if (struct.isSetCreateTime()) {
        oprot.writeFieldBegin(CREATE_TIME_FIELD_DESC);
        oprot.writeI64(struct.createTime);
        oprot.writeFieldEnd();
      }
      if (struct.grantOption != null) {
        if (struct.isSetGrantOption()) {
          oprot.writeFieldBegin(GRANT_OPTION_FIELD_DESC);
          oprot.writeI32(struct.grantOption.getValue());
          oprot.writeFieldEnd();
        }
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class TPrivilegeTupleSchemeFactory implements SchemeFactory {
    public TPrivilegeTupleScheme getScheme() {
      return new TPrivilegeTupleScheme();
    }
  }

  private static class TPrivilegeTupleScheme extends TupleScheme<TPrivilege> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, TPrivilege struct) throws org.apache.thrift.TException {
      TTupleProtocol oprot = (TTupleProtocol) prot;
      oprot.writeString(struct.action);
      BitSet optionals = new BitSet();
      if (struct.isSetCreateTime()) {
        optionals.set(0);
      }
      if (struct.isSetGrantOption()) {
        optionals.set(1);
      }
      oprot.writeBitSet(optionals, 2);
      if (struct.isSetCreateTime()) {
        oprot.writeI64(struct.createTime);
      }
      if (struct.isSetGrantOption()) {
        oprot.writeI32(struct.grantOption.getValue());
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, TPrivilege struct) throws org.apache.thrift.TException {
      TTupleProtocol iprot = (TTupleProtocol) prot;
      struct.action = iprot.readString();
      struct.setActionIsSet(true);
      BitSet incoming = iprot.readBitSet(2);
      if (incoming.get(0)) {
        struct.createTime = iprot.readI64();
        struct.setCreateTimeIsSet(true);
      }
      if (incoming.get(1)) {
        struct.grantOption = org.apache.sentry.api.service.thrift.TSentryGrantOption.findByValue(iprot.readI32());
        struct.setGrantOptionIsSet(true);
      }
    }
  }

}

