#!/usr/bin/env bash

#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Script to create a binary distribution for easy deploys of Spark.
# The distribution directory defaults to dist/ but can be overridden below.
# The distribution contains fat (assembly) jars that include the Scala library,
# so it is completely self contained.
# It does not contain source or *.class files.

set -e
set -x

if [ -z "$1" ]
  then
    echo "No argument supplied"
    exit 1
fi

# Figure out where the Spark framework is installed
SPARK_HOME="$(cd "`dirname "$0"`/.."; pwd)"
DISTDIR="$SPARK_HOME/dist"

VERSION=$1

echo "Making stratio-spark-distribution-${VERSION}-bin.tgz"


# Build uber fat JAR
cd "$SPARK_HOME"

# Make directories
rm -rf "$DISTDIR"
mkdir -p "$DISTDIR/jars"
echo "Spark $VERSION$GITREVSTRING built for Hadoop $SPARK_HADOOP_VERSION" > "$DISTDIR/RELEASE"
echo "Build flags: $@" >> "$DISTDIR/RELEASE"

# Copy jars
cp "$SPARK_HOME"/assembly/target/scala*/jars/* "$DISTDIR/jars/"

# Copy examples and dependencies
mkdir -p "$DISTDIR/examples/jars"
cp "$SPARK_HOME"/examples/target/scala*/jars/* "$DISTDIR/examples/jars"

# Deduplicate jars that have already been packaged as part of the main Spark dependencies.
for f in "$DISTDIR/examples/jars/"*; do
  name=$(basename "$f")
  if [ -f "$DISTDIR/jars/$name" ]; then
    rm "$DISTDIR/examples/jars/$name"
  fi
done

# Copy example sources (needed for python and SQL)
mkdir -p "$DISTDIR/examples/src/main"
cp -r "$SPARK_HOME"/examples/src/main "$DISTDIR/examples/src/"

# Copy license and ASF files
cp "$SPARK_HOME/LICENSE" "$DISTDIR"
cp -r "$SPARK_HOME/licenses" "$DISTDIR"
cp "$SPARK_HOME/NOTICE" "$DISTDIR"


# Copy data files
cp -r "$SPARK_HOME/data" "$DISTDIR"

# Copy other things
mkdir "$DISTDIR"/conf
cp "$SPARK_HOME"/conf/*.template "$DISTDIR"/conf
cp "$SPARK_HOME/README.md" "$DISTDIR"
cp -r "$SPARK_HOME/bin" "$DISTDIR"
cp -r "$SPARK_HOME/python" "$DISTDIR"


cp -r "$SPARK_HOME/sbin" "$DISTDIR"
# Copy SparkR if it exists
if [ -d "$SPARK_HOME"/R/lib/SparkR ]; then
  mkdir -p "$DISTDIR"/R/lib
  cp -r "$SPARK_HOME/R/lib/SparkR" "$DISTDIR"/R/lib
  cp "$SPARK_HOME/R/lib/sparkr.zip" "$DISTDIR"/R/lib
fi

TARDIR_NAME=stratio-spark-distribution-${VERSION}-bin
TARDIR="$SPARK_HOME/$TARDIR_NAME"
rm -rf "$TARDIR"
cp -r "$DISTDIR" "$TARDIR"
tar czf "stratio-spark-distribution-${VERSION}-bin.tgz" -C "$SPARK_HOME" "$TARDIR_NAME"
rm -rf "$TARDIR"

