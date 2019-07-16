/* Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */


package com.aws.iot.config;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

public class Topics extends Node implements Iterable<Node> {
    Topics(String n, Topics p) {
        super(n, p);
    }
    public final ConcurrentHashMap<String, Node> children = new ConcurrentHashMap<>();
    public void appendValueTo(Appendable a) throws IOException {
        a.append(String.valueOf(children));
    }
    @Override
    public void appendTo(Appendable a) throws IOException {
        appendNameTo(a);
        a.append(':');
        appendValueTo(a);
    }
    public Node getChild(String name) {
        return children.get(name);
    }
    Topic createLeafChild(String name) {
        Node n = children.computeIfAbsent(name, (nm) -> new Topic(nm, Topics.this));
        if (n instanceof Topic)
            return (Topic) n;
        else
            throw new IllegalArgumentException(name + " in " + this + " is already a container, cannot become a leaf");
    }
    Topics createInteriorChild(String name) {
        Node n = children.computeIfAbsent(name, (nm) -> new Topics(nm, Topics.this));
        if (n instanceof Topics)
            return (Topics) n;
        else
            throw new IllegalArgumentException(name + " in " + this + " is already a leaf, cannot become a container");
    }
    Topics findInteriorChild(String name) {
        Node n = getChild(name);
        return n instanceof Topics ? (Topics) n : null;
    }
    Topic findLeafChild(String name) {
        Node n = getChild(name);
        return n instanceof Topic ? (Topic) n : null;
    }
    void publish(Topic t) {
        fire(Configuration.WhatHappened.childChanged, t, null);
    }
    public void mergeMap(long t, Map<Object, Object> map) {
        map.forEach((okey, value) -> {
            String key = okey.toString();
            if (value instanceof Map)
                createInteriorChild(key).mergeMap(t, (Map) value);
            else
                createLeafChild(key).setValue(t, value);
        });
    }
    @Override
    public boolean equals(Object o) {
        if (o instanceof Topics) {
            Topics t = (Topics) o;
            if (children.size() == t.children.size()) {
                for (Map.Entry<String, Node> me : children.entrySet()) {
                    Object mov = t.children.get(me.getKey());
                    if (!Objects.equals(me.getValue(), mov))
                        //                            System.out.println(me.getKey() + "\t" + me.getValue() +
                        //                                    "\n\t" + t.children.get(me.getKey()));
                        return false;
                }
                return true;
            }
        }
        return false;
    }
    @Override
    public int hashCode() {
        return Objects.hashCode(children);
    }
    @Override
    public Iterator<Node> iterator() {
        return children.values().iterator();
    }
    @Override
    public void deepForEachTopic(Consumer<Topic> f) {
        children.values().forEach((t) -> t.deepForEachTopic(f));
    }
    public void forEachTopicSet(Consumer<Topics> f) {
        children.values().forEach((t) -> {
            if (t instanceof Topics)
                f.accept((Topics) t);
        });
    }
    public void remove(Node n) {
        if (!children.remove(n.name, n))
            System.err.println("remove: Missing node " + n.name + " from " + toString());
        n.fire(Configuration.WhatHappened.removed, null, null);
        fire(Configuration.WhatHappened.childRemoved, n, null);
    }
    @Override
    public Map<String, Object> toPOJO() {
        Map<String, Object> map = new TreeMap(String.CASE_INSENSITIVE_ORDER);
        children.values().forEach((n) -> map.put(n.name, n.toPOJO()));
        return map;
    }
    public static Topics errorNode(String name, String message) {
        Topics t = new Topics(name, null);
        t.createLeafChild("error").setValue(0, message);
        return t;
    }

}