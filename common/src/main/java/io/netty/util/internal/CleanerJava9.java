/*
* Copyright 2017 The Netty Project
*
* The Netty Project licenses this file to you under the Apache License,
* version 2.0 (the "License"); you may not use this file except in compliance
* with the License. You may obtain a copy of the License at:
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
* License for the specific language governing permissions and limitations
* under the License.
*/
package io.netty.util.internal;

import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

/**
 * Provide a way to clean a ByteBuffer on Java9+.
 */
final class CleanerJava9 implements Cleaner {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(CleanerJava9.class);

    private static final Method INVOKE_CLEANER;

    static {
        assert PlatformDependent0.UNSAFE != null;
        Method method;
        ByteBuffer buffer = ByteBuffer.allocateDirect(1);
        Object maybeInvokeMethod;
        try {
            // See https://bugs.openjdk.java.net/browse/JDK-8171377
            Method m = PlatformDependent0.UNSAFE.getClass().getDeclaredMethod("invokeCleaner", ByteBuffer.class);
            m.invoke(PlatformDependent0.UNSAFE, buffer);
            maybeInvokeMethod = m;
        } catch (NoSuchMethodException e) {
            maybeInvokeMethod = e;
        } catch (InvocationTargetException e) {
            maybeInvokeMethod = e;
        } catch (IllegalAccessException e) {
            maybeInvokeMethod = e;
        }
        if (maybeInvokeMethod instanceof Throwable) {
            method = null;
            logger.debug("java.nio.ByteBuffer.cleaner(): unavailable", (Throwable) maybeInvokeMethod);
        } else {
            method = (Method) maybeInvokeMethod;
            logger.debug("java.nio.ByteBuffer.cleaner(): available");
        }
        INVOKE_CLEANER = method;
    }

    private static void freeDirectBuffer0(ByteBuffer buffer) {
        if (INVOKE_CLEANER == null) {
            return;
        }
        try {
            INVOKE_CLEANER.invoke(PlatformDependent0.UNSAFE, buffer);
        } catch (Throwable ignore) {
            // Nothing we can do here.
        }
    }

    @Override
    public void freeDirectBuffer(ByteBuffer buffer) {
        freeDirectBuffer0(buffer);
    }
}
