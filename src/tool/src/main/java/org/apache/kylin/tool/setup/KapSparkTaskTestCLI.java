/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kylin.tool.setup;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.kylin.common.util.Unsafe;
import org.apache.spark.SparkConf;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;

import scala.Tuple2;

public class KapSparkTaskTestCLI {

    private static final Pattern SPACE = Pattern.compile(" ");

    public static void main(String[] args) {

        if (args.length < 1) {
            System.err.println("Usage: KapSparkTaskTestCLI <file>");
            Unsafe.systemExit(1);
        }

        SparkConf sparkConf = new SparkConf().setAppName("KAP Test Submit Spark Task");
        try (JavaSparkContext ctx = new JavaSparkContext(sparkConf)) {
            JavaRDD<String> lines = ctx.textFile(args[0], 1);

            List<Tuple2<String, Integer>> output = lines.flatMap(s -> Arrays.asList(SPACE.split(s)).iterator())
                    .mapToPair(s -> new Tuple2<>(s, 1)).reduceByKey((i1, i2) -> i1 + i2).collect();
            for (Tuple2<?, ?> tuple : output) {
                System.out.println(tuple._1() + ": " + tuple._2());
            }
            ctx.stop();
        }
    }
}
