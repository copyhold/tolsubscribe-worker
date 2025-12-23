/**
	{

  name: 'de subscribe form',
  siteId: '5e15e5b8274eec0840bcca74',
  data: {
    FNAME: 'adushoij',
    'EMAIL 3': 'novojilov.ilya+de0133@gmail.com',
    language: '88b70e0949',
    MMERGE25: 'https://www.treeoflifeisrael.org/de/about-us'
  },
  submittedAt: '2025-12-23T06:26:32.622Z',
  id: '694a3618555793d7896a4112',
  formId: '673e09da6d495908c844f354',
  formElementId: '350518f6-61da-0cbe-77cb-e8add4d76952',
  pageId: '632d5e80c45d986d8bd30914',
  publishedPath: '/de/about-us',
  pageUrl: 'https://www.treeoflifeisrael.org/de/about-us',
  schema: []
**/

import crypto from 'node:crypto';
const verifySignature = async ({ headers, body, secret }) => {
	// Creates a HMAC signature following directions from https://developers.webflow.com/data/docs/working-with-webhooks#steps-to-validate-the-request-signature
	const createHmac = async (signingSecret, message) => {
		console.log('createHmac', signingSecret, message);
		const encoder = new TextEncoder();

		// Encode the signingSecret key
		const key = await crypto.subtle.importKey('raw', encoder.encode(signingSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

		// Encode the message and compute HMAC signature
		const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));

		// Convert signature to hex string
		return Array.from(new Uint8Array(signature))
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');
	};

	const message = `${headers.get('x-webflow-timestamp')}:${body}`;

	const generatedSignature = await createHmac(secret, message);
	return headers.get('x-webflow-signature') === generatedSignature;
};

export default {
	async fetch(request, env) {
		if (request.method !== 'POST') {
			return new Response('Method Not Allowed', { status: 405 });
		}

		let payload;
		try {
			payload = await request.json();
		} catch {
			return new Response('Invalid JSON', { status: 400 });
		}

		console.debug(payload, Array.from(request.headers));

		const isRequestAuthValid = await verifySignature({
			headers: request.headers,
			body: JSON.stringify(payload),
			secret: env.WEBFLOW_REQUEST_AUTH,
		});
		if (!isRequestAuthValid) {
			console.debug('auth token not validated');
			return new Response('Auth token is not valid', { status: 403 });
		}

		if (payload.triggerType !== 'form_submission') {
			console.debug('request is not a form submission');
			return new Response('request is not a form submission', { status: 400 });
		}

		const form = payload.payload;
		if (
			![
				,
				'ko subscribe form',
				'de subscribe form',
				'cn subscribe form',
				'tw subscribe form',
				'pt subscribe form',
				'es subscribe form',
			].includes(form.name)
		) {
			console.debug(`invalid form submitted: ${form.name}`);
			return new Response(`not processing this form ${form.id}`, { status: 200 });
		}

		const { data } = form;
		const name = data.FNAME;
		const page = data.MMERGE25;

		const emails = [data.EMAIL, data['EMAIL 3'], data['EMAIL 5']];
		const email = emails.find(Boolean);

		const languages = [data.language, data['language 2']];
		const language = languages.find(Boolean) ?? 'eac26b8e85'; // default EN

		if (!email) {
			console.debug(`not found email: ${form}`);
			return new Response('Email not found', { status: 400 });
		}

		const contact = {
			email_address: email,
			status: 'subscribed',
			interests: language ? { [language]: true } : {},
			merge_fields: {
				FNAME: name,
				ENSFNAME: name,
				DEFNAME: name,
				DESFNAME: name,
				ESFNAME: name,
				ESSFNAME: name,
				PTFNAME: name,
				PTSFNAME: name,
				TWFNAME: name,
				TWSFNAME: name,
				KOFNAME: name,
				KOSFNAME: name,
				CNFNAME: name,
				CNSFNAME: name,
				MMERGE25: page,
			},
		};

		const apiKey = env.MAILCHIMP_API_KEY;
		const server = env.MAILCHIMP_API_SERVER; // e.g. "us21"
		const listId = env.MAILCHIMP_WEBFLOW_LIST;

		const url = `https://${server}.api.mailchimp.com/3.0/lists/${listId}/members?skip_merge_validation=1`;

		try {
			const res = await fetch(url, {
				method: 'POST',
				headers: {
					Authorization: `Basic ${btoa(`anystring:${apiKey}`)}`,
					'Content-Type': 'application/json',
				},
				body: JSON.stringify(contact),
			});

			const data = await res.json();

			if (!res.ok) {
				console.log('failed to send to mailchimp', data, res.status);
				return new Response(JSON.stringify({ error: data }), { status: res.status, headers: { 'Content-Type': 'application/json' } });
			}

			console.log('created subscription in mailchimp', email);
			return new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
		} catch (err) {
			console.log('failed to send to mailchimp', err);
			return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
		}
	},
};
