/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.util;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItems;

@ExtendWith(GGExtension.class)
public class DependencyOrderTest {
    @Test
    public void testHappyCase() {
        Map<String, Set<String>> tree = new HashMap<String, Set<String>>() {{
            put("A", new HashSet<>(Arrays.asList("B", "C")));
            put("B", new HashSet<>(Arrays.asList("C")));
            put("C", Collections.emptySet());
        }};
        LinkedHashSet<String> result = new DependencyOrder<String>().computeOrderedDependencies(
                tree.keySet(), name -> tree.get(name));
        assertThat(result, hasItems("C", "B", "A"));
    }

    @Test
    public void testCircularDependencies() {
        Map<String, Set<String>> tree = new HashMap<String, Set<String>>() {{
            put("A", new HashSet<>(Arrays.asList("B", "C")));
            put("B", new HashSet<>(Arrays.asList("A")));
            put("C", Collections.emptySet());
        }};
        LinkedHashSet<String> result = new DependencyOrder<String>().computeOrderedDependencies(
                tree.keySet(), name -> tree.get(name));
        assertThat(result, hasItems("C"));
    }
}