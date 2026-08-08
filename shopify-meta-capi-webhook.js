/**
 * Webhook: Shopify "orders/paid" -> Meta Conversions API (evento Purchase)
 * ---------------------------------------------------------------------
 * Contexto: no checkout da Lívia Ribeiro, pedidos pagos via "Parcelamento"
 * ficam com status "pagamento pendente" até alguém marcar como pago
 * manualmente no admin da Shopify (depois da confirmação via Cielo).
 * O canal nativo Shopify->Meta só dispara o Purchase no momento do
 * checkout, e SÓ para pedidos que já nascem pagos (ex: PIX). Confirmado
 * por teste real: marcar um pedido como pago depois não gera o evento.
 *
 * Este webhook resolve isso: toda vez que um pedido é marcado como pago
 * (endpoint "orders/paid" da Shopify, dispara tanto na compra via PIX
 * quanto no "Marcar como pago" manual do Parcelamento), este script
 * envia o evento Purchase para a Meta via API de Conversões — cobrindo
 * o gap.
 *
 * DEPLOY (qualquer opção serve, é só uma function HTTP):
 *   - Vercel: crie um projeto, coloque este arquivo em /api/meta-capi.js,
 *     "vercel deploy". A URL fica algo como
 *     https://seu-projeto.vercel.app/api/meta-capi
 *   - Cloudflare Workers: adaptar para o formato de Workers (fetch handler)
 *   - Qualquer Node host com Express: app.post('/webhook', handler)
 *
 * CONFIGURAÇÃO NA SHOPIFY (depois de ter a URL pública):
 *   Admin > Configurações > Notificações > Webhooks > Criar webhook
 *   Evento: "Pedido pago" (orders/paid)
 *   Formato: JSON
 *   URL: <sua URL de deploy>
 *   Isso te dá também o "Signing secret" (SHOPIFY_WEBHOOK_SECRET abaixo).
 *
 * VARIÁVEIS DE AMBIENTE NECESSÁRIAS:
 *   META_PIXEL_ID              = 828033213432275   (já confirmado)
 *   META_CAPI_ACCESS_TOKEN     = gerar em Events Manager > Pixel > Configurações
 *                                 > API de Conversões > "Configurar integração
 *                                 direta" > "Gerar token de acesso"
 *   SHOPIFY_WEBHOOK_SECRET     = fornecido pela Shopify ao criar o webhook
 *                                 (usado para validar a assinatura HMAC)
 *   META_TEST_EVENT_CODE       = opcional, só para testar em
 *                                 Events Manager > Eventos de teste antes
 *                                 de ativar em produção (remover depois)
 */

const crypto = require('crypto');

// ---- Config (via variáveis de ambiente) ----
const PIXEL_ID = process.env.META_PIXEL_ID;
const ACCESS_TOKEN = process.env.META_CAPI_ACCESS_TOKEN;
const WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const TEST_EVENT_CODE = process.env.META_TEST_EVENT_CODE; // opcional
const GRAPH_VERSION = 'v21.0';

function sha256(value) {
  if (!value) return undefined;
  return crypto
    .createHash('sha256')
    .update(String(value).trim().toLowerCase())
    .digest('hex');
}

// Normaliza telefone para E.164 antes de hashear (Meta exige isso para bater)
function normalizePhone(raw, defaultCountryCode = '55') {
  if (!raw) return undefined;
  const digits = String(raw).replace(/\D/g, '');
  if (!digits) return undefined;
  // Se já vier com código do país (ex: 55...), usa direto; senão prefixa.
  const withCountry = digits.startsWith(defaultCountryCode)
    ? digits
    : `${defaultCountryCode}${digits}`;
  return withCountry;
}

function verifyShopifyHmac(rawBody, hmacHeader) {
  if (!WEBHOOK_SECRET) return true; // sem secret configurado, pula validação (não recomendado em produção)
  const digest = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody, 'utf8')
    .digest('base64');
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader || ''));
}

function buildPurchaseEvent(order) {
  const email = order?.email || order?.contact_email;
  const phone = order?.phone || order?.shipping_address?.phone || order?.customer?.phone;
  const firstName = order?.customer?.first_name || order?.shipping_address?.first_name;
  const lastName = order?.customer?.last_name || order?.shipping_address?.last_name;
  const city = order?.shipping_address?.city;
  const state = order?.shipping_address?.province_code;
  const zip = order?.shipping_address?.zip;
  const country = order?.shipping_address?.country_code;

  // external_id ajuda a deduplicar/casar com outros eventos do mesmo cliente
  const externalId = order?.customer?.id ? String(order.customer.id) : undefined;

  const userData = {
    em: sha256(email),
    ph: sha256(normalizePhone(phone)),
    fn: sha256(firstName),
    ln: sha256(lastName),
    ct: sha256(city),
    st: sha256(state),
    zp: sha256(zip),
    country: sha256(country),
    external_id: sha256(externalId),
  };

  // fbc/fbp: se você salvar esses cookies como "note attributes" do pedido
  // no momento do checkout (via um pequeno script no tema), pode reenviá-los
  // aqui para melhorar MUITO a qualidade de correspondência. Ver seção
  // "Melhoria opcional" no final do arquivo.
  const fbp = order?.note_attributes?.find((a) => a.name === '_fbp')?.value;
  const fbc = order?.note_attributes?.find((a) => a.name === '_fbc')?.value;
  if (fbp) userData.fbp = fbp;
  if (fbc) userData.fbc = fbc;

  const contents = (order?.line_items || []).map((item) => ({
    id: String(item.product_id || item.variant_id || item.sku || ''),
    quantity: item.quantity,
    item_price: Number(item.price),
  }));

  const event = {
    event_name: 'Purchase',
    event_time: Math.floor(new Date(order.processed_at || order.created_at).getTime() / 1000),
    action_source: 'website',
    event_source_url: `https://liviaribeiro.com/checkouts/order/${order.order_status_url ? '' : ''}`.replace(/\/$/, ''),
    user_data: userData,
    custom_data: {
      currency: order?.currency || 'BRL',
      value: Number(order?.total_price || order?.current_total_price || 0),
      contents,
      content_type: 'product',
      order_id: String(order?.id || order?.order_number || ''),
    },
    // Evita duplicar caso o mesmo pedido gere dois webhooks (ex: paid + edited)
    event_id: `shopify_order_paid_${order?.id}`,
  };

  return event;
}

async function sendToMetaCapi(event) {
  const body = {
    data: [event],
  };
  if (TEST_EVENT_CODE) {
    body.test_event_code = TEST_EVENT_CODE;
  }

  const url = `https://graph.facebook.com/${GRAPH_VERSION}/${PIXEL_ID}/events?access_token=${ACCESS_TOKEN}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const json = await res.json();
  if (!res.ok) {
    throw new Error(`Meta CAPI error: ${JSON.stringify(json)}`);
  }
  return json;
}

// ---- Handler HTTP (formato Vercel/Node genérico) ----
// Adaptar a assinatura conforme a plataforma de deploy escolhida.
module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed');
    return;
  }

  try {
    // Importante: para validar o HMAC corretamente é preciso o corpo RAW,
    // antes de qualquer parse automático de JSON pelo framework.
    const rawBody = req.rawBody || JSON.stringify(req.body);
    const hmacHeader = req.headers['x-shopify-hmac-sha256'];

    if (!verifyShopifyHmac(rawBody, hmacHeader)) {
      res.status(401).send('Assinatura inválida');
      return;
    }

    const order = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

    // Só processa se o pedido de fato está pago (financial_status == paid)
    if (order.financial_status !== 'paid') {
      res.status(200).send('Ignorado: pedido não está pago');
      return;
    }

    const event = buildPurchaseEvent(order);
    const result = await sendToMetaCapi(event);

    console.log('Purchase enviado para Meta CAPI:', order.id, result);
    res.status(200).json({ ok: true, result });
  } catch (err) {
    console.error('Erro ao processar webhook:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
};

/**
 * MELHORIA OPCIONAL (recomendada, mas não bloqueante):
 * Capturar _fbp e _fbc no checkout e salvar como note_attributes do pedido,
 * para reenviar aqui como user_data.fbp / user_data.fbc. Isso aumenta muito
 * a taxa de correspondência (hoje o pixel está em 6.0/10, meta é 7.66+).
 * Sem isso, o evento ainda funciona e conta para o volume de conversão,
 * só a atribuição direta a um clique de anúncio específico fica mais fraca
 * (mas isso já é uma melhoria enorme em relação a não enviar nada).
 *
 * TESTE ANTES DE ATIVAR EM PRODUÇÃO:
 * 1. Gere um Test Event Code em Events Manager > Pixel > Eventos de teste.
 * 2. Configure META_TEST_EVENT_CODE temporariamente.
 * 3. Marque um pedido de teste como pago e confira se o evento aparece
 *    na aba "Eventos de teste" do Events Manager, com os campos certos.
 * 4. Remova META_TEST_EVENT_CODE antes de ir para produção.
 */
