/*
 * Copyright 2013 The Netty Project
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

package io.netty.handler.ssl;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.util.CharsetUtil;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.Test;

import javax.net.ssl.*;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.cert.Certificate;

public class SslHandlerTest {

    private static final InternalLogger logger = InternalLoggerFactory.getInstance(SslHandlerTest.class);

    private final SecureRandom sr = new SecureRandom();

    @Test
    public void testTruncatedPacket() throws Exception {
        SSLEngine engine = SSLContext.getDefault().createSSLEngine();
        engine.setUseClientMode(false);

        EmbeddedChannel ch = new EmbeddedChannel(new SslHandler(engine));

        // Push the first part of a 5-byte handshake message.
        ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{22, 3, 1, 0, 5}));

        // Should decode nothing yet.
        assertThat(ch.readInbound(), is(nullValue()));

        try {
            // Push the second part of the 5-byte handshake message.
            ch.writeInbound(Unpooled.wrappedBuffer(new byte[]{2, 0, 0, 1, 0}));
            fail();
        } catch (DecoderException e) {
            // The pushed message is invalid, so it should raise an exception if it decoded the message correctly.
            assertThat(e.getCause(), is(instanceOf(SSLProtocolException.class)));
        }
    }

    @Test
    public void testNonByteBufPassthrough() throws Exception {
        SSLEngine engine = SSLContext.getDefault().createSSLEngine();
        engine.setUseClientMode(false);

        EmbeddedChannel ch = new EmbeddedChannel(new SslHandler(engine));

        Object msg1 = new Object();
        ch.writeOutbound(msg1);
        assertThat(ch.readOutbound(), is(sameInstance(msg1)));

        Object msg2 = new Object();
        ch.writeInbound(msg2);
        assertThat(ch.readInbound(), is(sameInstance(msg2)));

        ch.finish();
    }

    private KeyPair genKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024, sr);
        return keyGen.generateKeyPair();
    }

    private X509Certificate genCert(KeyPair keyPair) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        String commonName = "localhost";
        X509Name x509Name = new X509Name("CN=" + commonName);

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(x509Name);
        certGen.setSubjectDN(x509Name);
        certGen.setSignatureAlgorithm("SHA1withRSA");
        certGen.setPublicKey(pubKey);
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 1));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 60 * 60 * 1000));

        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.keyEncipherment));
        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
                KeyPurposeId.id_kp_serverAuth));

        X509Certificate cert = certGen.generate(privKey);
        cert.verify(pubKey);
        return cert;
    }

    private KeyStore genKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchProviderException, SignatureException {
        KeyPair keyPair = genKeyPair();
        X509Certificate cert = genCert(keyPair);
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("test-cert", keyPair.getPrivate(), new char[] {}, new Certificate[] {cert});
        return ks;
    }

    private SSLContext genServerContext(KeyStore ks) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        SSLContext serverContext = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");

        kmf.init(ks, new char[] {});

        KeyManager[] kms = kmf.getKeyManagers();
        serverContext.init(kms, null, sr);
        return serverContext;
    }

    private SSLContext genClientContext(KeyStore ks) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException {
        SSLContext clientContext = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        clientContext.init(null, tmf.getTrustManagers(), sr);
        return clientContext;
    }

    @Test
    public void testTimeoutOnClose() throws NoSuchAlgorithmException, InterruptedException, IOException, KeyStoreException, CertificateException, SignatureException, InvalidKeyException, NoSuchProviderException, UnrecoverableKeyException, KeyManagementException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        final CountDownLatch latch = new CountDownLatch(1);
        EventLoopGroup clientGroup = new NioEventLoopGroup(1, new DefaultThreadFactory("client"));
        EventLoopGroup serverGroup = new NioEventLoopGroup(1, new DefaultThreadFactory("server"));

        // Generate a cert + key
        KeyStore ks = genKeyStore();

        InetAddress addr = InetAddress.getLocalHost();
        int port = 12345;

        Bootstrap cb = new Bootstrap();
        ServerBootstrap sb = new ServerBootstrap();

        SSLContext serverContext = genServerContext(ks);
        SSLContext clientContext = genClientContext(ks);


        SSLEngine clientEngine = clientContext.createSSLEngine();
        clientEngine.setUseClientMode(true);
        final SslHandler clientHandler = new SslHandler(clientEngine);

        SSLEngine serverEngine = serverContext.createSSLEngine();
        serverEngine.setUseClientMode(false);
        final SslHandler serverHandler = new SslHandler(serverEngine);
        serverHandler.setCloseNotifyTimeout(5, TimeUnit.MILLISECONDS);

        final DelayHandler delayer = new DelayHandler();
        cb.group(clientGroup)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<NioSocketChannel>() {
                    @Override
                    protected void initChannel(NioSocketChannel ch) throws Exception {
                        ChannelPipeline pipeline = ch.pipeline();
                        pipeline.addLast("ssl", clientHandler);
                        pipeline.addLast("test", new TestHandler(latch, delayer));
                    }
                });


        sb.group(serverGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<NioSocketChannel>() {

                    @Override
                    protected void initChannel(NioSocketChannel ch) throws Exception {
                        ch.pipeline()
                                .addLast("delay", delayer)
                                .addLast("ssl", serverHandler)
                                .addLast("echo", new EchoHandler());
                    }
                });

        Channel sc = sb.bind(addr, port).sync().channel();

        final Channel cc = cb.connect(addr, port).sync().channel();

        assertTrue("Failed to complete test, likely an exception in another thread", latch.await(3, TimeUnit.SECONDS));
    }

    static class DelayHandler extends ChannelOutboundHandlerAdapter {

        public boolean allowFlush = true;
        private boolean closed = false;
        private CountDownLatch latch;

        @Override
        public void flush(final ChannelHandlerContext ctx) throws InterruptedException {
            if (allowFlush) {
                ctx.flush();
            } else {
                //allowFlush = true;
                logger.info("Delaying a flush");
                if (!closed) {
                    closed = true;
                    ChannelPromise p = ctx.newPromise();
                    ctx.channel().close(p).addListener(new ChannelFutureListener() {
                        @Override
                        public void operationComplete(ChannelFuture future) throws Exception {
                            logger.info("Close complete");
                        }
                    });
                    ctx.executor().schedule(new Runnable() {
                        @Override
                        public void run() {
                            allowFlush = true;
                            ctx.flush();
                        }
                    }, 10, TimeUnit.MILLISECONDS);
                }
            }
        }
    }

    static class EchoHandler extends ChannelInboundHandlerAdapter {

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ctx.writeAndFlush(msg);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable t) {
            logger.info("caught exception");
        }
    }

    static class TestHandler extends ChannelInboundHandlerAdapter {

        private CountDownLatch latch;
        private DelayHandler delayer;

        TestHandler(CountDownLatch latch, DelayHandler delayer) {
            this.latch = latch;
            this.delayer = delayer;
        }

        /*@Override
        public void channelActive(ChannelHandlerContext ctx) {

        }*/

        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object event) {
            logger.info("Event triggered: " + event);
            if (event instanceof SslHandshakeCompletionEvent) {
                SslHandshakeCompletionEvent evt = (SslHandshakeCompletionEvent) event;
                if (evt.isSuccess()) {
                    logger.info("Handshake complete");
                    delayer.allowFlush = false;
                    logger.info("Writing message");
                    ByteBuf msg = Unpooled.copiedBuffer("foo", CharsetUtil.UTF_8);
                    ctx.writeAndFlush(msg);
                } else {
                    logger.info("Handshake failed");
                }
            } else {
                logger.info("Unknown event: " + event);
            }
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            logger.info(String.format("Received message: %s", msg));
            latch.countDown();
        }
    }
}
