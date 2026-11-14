package com.mathinet.tienda;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/** Muestra la tienda Mathi Net dentro de la app. */
public class MainActivity extends Activity {

    /** Direccion "de mentira" con la que se carga la tienda guardada, para que el navegador interno la trate como pagina segura. */
    private static final String BASE = "https://tienda.mathinet.app/";

    private WebView web;
    private String remoteHost = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        web = new WebView(this);
        web.setBackgroundColor(getResources().getColor(R.color.fondo));
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(getResources().getColor(R.color.fondo));
        root.addView(web, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        // Deja libre el lugar de la barra de estado y de los botones del telefono.
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(root);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setJavaScriptCanOpenWindowsAutomatically(true);

        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return openOutside(request.getUrl());
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                // Si la tienda online no carga (sin internet), se muestra la copia guardada en la app.
                if (request.isForMainFrame() && !remoteHost.isEmpty()) {
                    remoteHost = "";
                    loadBundled();
                }
            }
        });

        if (savedInstanceState != null) {
            web.restoreState(savedInstanceState);
            return;
        }

        String remote = getString(R.string.remote_url).trim();
        if (remote.startsWith("https://")) {
            remoteHost = Uri.parse(remote).getHost();
            if (remoteHost == null) remoteHost = "";
            web.loadUrl(remote);
        } else {
            loadBundled();
        }
    }

    /** Carga la tienda guardada en app/src/main/assets/index.html */
    private void loadBundled() {
        try (InputStream in = getAssets().open("index.html")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            web.loadDataWithBaseURL(BASE, out.toString("UTF-8"), "text/html", "UTF-8", null);
        } catch (Exception e) {
            Toast.makeText(this, "No se pudo abrir la tienda.", Toast.LENGTH_LONG).show();
        }
    }

    /** Los enlaces de la tienda quedan en la app; WhatsApp, Play Store y el resto se abren afuera. */
    private boolean openOutside(Uri uri) {
        String url = uri.toString();
        String host = uri.getHost() == null ? "" : uri.getHost();
        boolean inside = url.startsWith(BASE) || (!remoteHost.isEmpty() && host.equals(remoteHost));
        if (inside) return false;
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, uri));
        } catch (Exception e) {
            Toast.makeText(this, "No hay una app para abrir este enlace.", Toast.LENGTH_LONG).show();
        }
        return true;
    }

    /** Boton Atras: primero cierra el producto abierto; si no hay ninguno, sale de la app. */
    @Override
    public void onBackPressed() {
        web.evaluateJavascript(
                "(function(){try{if(S.pid){S.pid=null;modal();return 1}}catch(e){}return 0})()",
                value -> {
                    if ("1".equals(value)) return;
                    if (web.canGoBack()) web.goBack(); else finish();
                });
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        web.saveState(outState);
    }
}
