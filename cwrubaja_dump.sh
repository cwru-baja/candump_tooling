#!/bin/bash

# Check if there are exactly two arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <candump.log>"
      exit 1
fi

./cyroner.py $1 \
  435:uavcan.node.ExecuteCommand \
  1632:uavcan.primitive.scalar.Bit \
  1730:uavcan.primitive.scalar.Bit \
  2346:uavcan.si.unit.angle.Quaternion \
  2347:uavcan.si.unit.angular_velocity.Vector3 \
  2348:uavcan.si.unit.acceleration.Vector3 \
  2351:uavcan.si.unit.length.Scalar \
  2357:uavcan.si.unit.length.Scalar \
  2371:uavcan.si.unit.length.Scalar \
  2377:uavcan.si.unit.length.Scalar \
  5051:cwrubaja.suspension.vcm.Status \
  5052:cwrubaja.suspension.vcm.Status \
  5053:cwrubaja.suspension.vcm.Status \
  5054:cwrubaja.suspension.vcm.Status \
  5556:cwrubaja.suspension.vcm.Setpoint \
  5557:cwrubaja.suspension.vcm.Setpoint \
  5558:cwrubaja.suspension.vcm.Setpoint \
  5559:cwrubaja.suspension.vcm.Setpoint \
  6051:cwrubaja.suspension.vcm.Setpoint \
  6057:cwrubaja.suspension.vcm.Setpoint \
  6071:cwrubaja.suspension.vcm.Setpoint \
  6077:cwrubaja.suspension.vcm.Setpoint
