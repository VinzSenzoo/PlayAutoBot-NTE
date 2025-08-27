import axios from 'axios';
import cfonts from 'cfonts';
import gradient from 'gradient-string';
import chalk from 'chalk';
import fs from 'fs/promises';
import readline from 'readline';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import ProgressBar from 'progress';
import ora from 'ora';
import { ethers } from 'ethers';

const logger = {
  info: (msg, options = {}) => {
    const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const emoji = options.emoji || 'ℹ️  ';
    const context = options.context ? `[${options.context}] ` : '';
    const level = chalk.green('INFO');
    const formattedMsg = `[ ${chalk.gray(timestamp)} ] ${emoji}${level} ${chalk.white(context.padEnd(20))}${chalk.white(msg)}`;
    console.log(formattedMsg);
  },
  warn: (msg, options = {}) => {
    const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const emoji = options.emoji || '⚠️  ';
    const context = options.context ? `[${options.context}] ` : '';
    const level = chalk.yellow('WARN');
    const formattedMsg = `[ ${chalk.gray(timestamp)} ] ${emoji}${level} ${chalk.white(context.padEnd(20))}${chalk.white(msg)}`;
    console.log(formattedMsg);
  },
  error: (msg, options = {}) => {
    const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const emoji = options.emoji || '❌  ';
    const context = options.context ? `[${options.context}] ` : '';
    const level = chalk.red('ERROR');
    const formattedMsg = `[ ${chalk.gray(timestamp)} ] ${emoji}${level} ${chalk.white(context.padEnd(20))}${chalk.white(msg)}`;
    console.log(formattedMsg);
  }
};

function delay(seconds) {
  return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

function stripAnsi(str) {
  return str.replace(/\x1B\[[0-9;]*m/g, '');
}

function centerText(text, width) {
  const cleanText = stripAnsi(text);
  const textLength = cleanText.length;
  const totalPadding = Math.max(0, width - textLength);
  const leftPadding = Math.floor(totalPadding / 2);
  const rightPadding = totalPadding - leftPadding;
  return `${' '.repeat(leftPadding)}${text}${' '.repeat(rightPadding)}`;
}

function printHeader(title) {
  const width = 80;
  console.log(gradient.morning(`┬${'─'.repeat(width - 2)}┬`));
  console.log(gradient.morning(`│ ${title.padEnd(width - 4)} │`));
  console.log(gradient.morning(`┴${'─'.repeat(width - 2)}┴`));
}

function printInfo(label, value, context) {
  logger.info(`${label.padEnd(15)}: ${chalk.cyan(value)}`, { emoji: '📍 ', context });
}

async function formatTaskTable(tasks, context) {
  console.log('\n');
  logger.info('Task List:', { context, emoji: '📋 ' });
  console.log('\n');

  const spinner = ora('Rendering tasks...').start();
  await new Promise(resolve => setTimeout(resolve, 1000));
  spinner.stop();

  const header = chalk.cyanBright('+----------------------+----------+-------+---------+\n| Task Name            | Category | Point | Status  |\n+----------------------+----------+-------+---------+');
  const rows = tasks.map(task => {
    const displayName = task.name && typeof task.name === 'string'
      ? (task.name.length > 20 ? task.name.slice(0, 17) + '...' : task.name)
      : 'Unknown Task';
    const category = ((task.type || 'N/A') + '     ').slice(0, 8);
    const points = ((task.credit || 0).toString() + '    ').slice(0, 5);
    const status = task.completed ? chalk.greenBright('Complte') : chalk.yellowBright('Pending');
    return `| ${displayName.padEnd(20)} | ${category} | ${points} | ${status.padEnd(6)} |`;
  }).join('\n');
  const footer = chalk.cyanBright('+----------------------+----------+-------+---------+');

  console.log(header + '\n' + rows + '\n' + footer);
  console.log('\n');
}

async function formatVoteTable(votes, context, isVerified = false) {
  console.log('\n');
  logger.info(isVerified ? 'Verified Vote List:' : 'Vote List:', { context, emoji: '🗳️  ' });
  console.log('\n');

  const spinner = ora(isVerified ? 'Rendering verified votes...' : 'Rendering votes...').start();
  await new Promise(resolve => setTimeout(resolve, 1000));
  spinner.stop();

  const header = chalk.cyanBright('+----------------------+-----------------+\n| Tweet Title          | Vote            |\n+----------------------+-----------------+');
  const rows = votes.map(vote => {
    const displayTitle = vote.title && typeof vote.title === 'string'
      ? (vote.title.length > 20 ? vote.title.slice(0, 17) + '...' : vote.title)
      : 'Unknown';
    let status;
    if (isVerified) {
      status = vote.vote ? chalk.greenBright('Voted YES') : chalk.redBright('Voted NO ');
    } else {
      status = vote.status ? chalk.greenBright(vote.status) : chalk.redBright('Failed');
    }
    return `| ${displayTitle.padEnd(20)} | ${status.padEnd(15)}       |`;
  }).join('\n');
  const footer = chalk.cyanBright('+----------------------+-----------------+');

  console.log(header + '\n' + rows + '\n' + footer);
  console.log('\n');
}

const userAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/102.0'
];

function getRandomUserAgent() {
  return userAgents[Math.floor(Math.random() * userAgents.length)];
}

function getGlobalHeaders(token = null) {
  const headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9,id;q=0.8',
    'priority': 'u=1, i',
    'referer': 'https://hub.playai.network/mining',
    'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    'sec-ch-ua-arch': '"x86"',
    'sec-ch-ua-bitness': '"64"',
    'sec-ch-ua-full-version': '"134.0.6998.89"',
    'sec-ch-ua-full-version-list': '"Chromium";v="134.0.6998.89", "Not:A-Brand";v="24.0.0.0", "Google Chrome";v="134.0.6998.89"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-model': '""',
    'sec-ch-ua-platform': '"Windows"',
    'sec-ch-ua-platform-version': '"19.0.0"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': getRandomUserAgent()
  };
  if (token) {
    headers['authorization'] = `Bearer ${token}`;
  }
  return headers;
}

function getAxiosConfig(proxy, token = null) {
  const config = {
    headers: getGlobalHeaders(token),
    timeout: 60000
  };
  if (proxy) {
    config.httpsAgent = newAgent(proxy);
    config.proxy = false;
  }
  return config;
}

function newAgent(proxy) {
  if (proxy.startsWith('http://') || proxy.startsWith('https://')) {
    return new HttpsProxyAgent(proxy);
  } else if (proxy.startsWith('socks4://') || proxy.startsWith('socks5://')) {
    return new SocksProxyAgent(proxy);
  } else {
    logger.warn(`Unsupported proxy: ${proxy}`);
    return null;
  }
}

async function requestWithRetry(method, url, payload = null, config = {}, retries = 3, backoff = 2000, context) {
  for (let i = 0; i < retries; i++) {
    try {
      let response;
      if (method.toLowerCase() === 'get') {
        response = await axios.get(url, config);
      } else if (method.toLowerCase() === 'post') {
        response = await axios.post(url, payload, config);
      } else {
        throw new Error(`Method ${method} not supported`);
      }
      return { success: true, response: response.data };
    } catch (error) {
      const status = error.response?.status;
      if (status === 400 || status === 404) {
        return { success: false, message: error.response?.data?.message || 'Bad request', status };
      }
      if (i < retries - 1) {
        logger.warn(`Retrying ${method.toUpperCase()} ${url} (${i + 1}/${retries})`, { emoji: '🔄  ', context });
        await delay(backoff / 1000);
        backoff *= 1.5;
        continue;
      }
      logger.error(`Request failed: ${error.message} - Status: ${status}`, { context });
      return { success: false, message: error.message, status };
    }
  }
}

const BASE_URL = 'https://hub-prod.engineering-87e.workers.dev';

async function readPrivateKeys() {
  try {
    const data = await fs.readFile('pk.txt', 'utf-8');
    const pks = data.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    logger.info(`Loaded ${pks.length} private key${pks.length === 1 ? '' : 's'}`, { emoji: '📄 ' });
    return pks;
  } catch (error) {
    logger.error(`Failed to read pk.txt: ${error.message}`, { emoji: '❌ ' });
    return [];
  }
}

async function readProxies() {
  try {
    const data = await fs.readFile('proxy.txt', 'utf-8');
    const proxies = data.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    if (proxies.length === 0) {
      logger.warn('No proxies found. Proceeding without proxy.', { emoji: '⚠️  ' });
    } else {
      logger.info(`Loaded ${proxies.length} prox${proxies.length === 1 ? 'y' : 'ies'}`, { emoji: '🌐  ' });
    }
    return proxies;
  } catch (error) {
    logger.warn('proxy.txt not found.', { emoji: '⚠️ ' });
    return [];
  }
}

async function getPublicIP(proxy, context) {
  try {
    const config = getAxiosConfig(proxy);
    delete config.headers.authorization;
    const response = await requestWithRetry('get', 'https://api.ipify.org?format=json', null, config, 3, 2000, context);
    return response.response.ip || 'Unknown';
  } catch (error) {
    logger.error(`Failed to get IP: ${error.message}`, { emoji: '❌  ', context });
    return 'Error retrieving IP';
  }
}

async function loginWithWallet(pk, proxy, context) {
  const spinner = ora({ text: 'Logging in with wallet...', spinner: 'dots' }).start();
  try {
    let cleanedPk = pk.trim();
    if (cleanedPk.startsWith('0x')) {
      cleanedPk = cleanedPk.slice(2);
    }
    if (cleanedPk.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(cleanedPk)) {
      throw new Error('Invalid Private Key Format.');
    }
    const fullPk = '0x' + cleanedPk;

    const wallet = new ethers.Wallet(fullPk);
    const address = wallet.address;

    const nonceRes = await requestWithRetry('get', `${BASE_URL}/auth/wallet`, null, getAxiosConfig(proxy), 3, 2000, context);
    if (!nonceRes.success) {
      throw new Error(nonceRes.message || 'Failed to get nonce');
    }
    if (!nonceRes.response || typeof nonceRes.response !== 'object') {
      throw new Error('Invalid response from nonce endpoint');
    }
    const { message, nonce } = nonceRes.response;
    if (!message || !nonce) {
      throw new Error('Missing message or nonce in response');
    }
    const signature = await wallet.signMessage(message);
    const payload = { nonce, signature, wallet: address };
    const authRes = await requestWithRetry('post', `${BASE_URL}/auth/wallet/evm`, payload, getAxiosConfig(proxy), 3, 2000, context);
    if (!authRes.success) {
      throw new Error(authRes.message || 'Authentication failed');
    }
    if (!authRes.response || !authRes.response.jwt) {
      throw new Error('Missing JWT in authentication response');
    }
    const jwt = authRes.response.jwt;

    spinner.stop();
    return { jwt, address };
  } catch (error) {
    spinner.fail(`Failed to login: ${error.message}`);
    return { error: error.message };
  }
}

async function performCheckin(token, proxy, context) {
  const spinner = ora({ text: 'Performing check-in...', spinner: 'dots' }).start();
  try {
    const res = await requestWithRetry('post', `${BASE_URL}/user/streak`, {}, getAxiosConfig(proxy, token), 3, 2000, context);
    if (res.success) {
      spinner.succeed(chalk.bold.greenBright('  Check-in successful'));
      return { success: true, data: res.response };
    } else {
      spinner.warn(chalk.bold.yellowBright('  Already Checkin Today'));
      return { success: false, message: res.message };
    }
  } catch (error) {
    spinner.fail(chalk.bold.redBright(`  Check-in failed: ${error.message}`));
    return { success: false, message: error.message };
  }
}

async function fetchMissions(token, proxy, context) {
  try {
    const res = await requestWithRetry('get', `${BASE_URL}/user/missions`, null, getAxiosConfig(proxy, token), 3, 2000, context);
    if (!res.success) {
      throw new Error(res.message);
    }
    return res.response.map(mission => ({
      id: mission.id,
      name: mission.name,
      type: mission.type,
      credit: mission.credit,
      completed: mission.completed
    }));
  } catch (error) {
    logger.error(`Failed to fetch missions: ${error.message}`, { context });
    return [];
  }
}

async function completeMission(token, mission, proxy, context) {
  const taskContext = `${context}|M${mission.id.slice(-6)}`;
  const spinner = ora({ text: `Verifying ${mission.name}...`, spinner: 'dots' }).start();
  try {
    const res = await requestWithRetry('post', `${BASE_URL}/user/missions/${mission.id}/verify`, {}, getAxiosConfig(proxy, token), 3, 2000, taskContext);
    if (res.success) {
      spinner.succeed(chalk.bold.greenBright(`  Verified: ${mission.name}`));
      return { success: true };
    } else if (res.status === 400) {
      spinner.warn(chalk.bold.yellowBright(`  ${res.message}`));
      return { success: false, message: res.message };
    } else {
      spinner.warn(chalk.bold.yellowBright('  Failed to Verify Task'));
      return { success: false, message: res.message };
    }
  } catch (error) {
    spinner.fail(chalk.bold.redBright(`Failed: ${error.message}`));
    return { success: false, message: error.message };
  }
}

async function fetchVoteQuota(token, proxy, context) {
  try {
    const res = await requestWithRetry('get', 'https://hub.playai.network/api/mining/quota/vote', null, getAxiosConfig(proxy, token), 3, 2000, context);
    if (!res.success) {
      throw new Error(res.message);
    }
    return res.response;
  } catch (error) {
    logger.error(`Failed to fetch vote quota: ${error.message}`, { context });
    return { remaining: 0, total: 0 };
  }
}

async function fetchTweets(token, proxy, context) {
  try {
    const res = await requestWithRetry('get', 'https://hub.playai.network/api/mining/tweets?page=1&limit=30', null, getAxiosConfig(proxy, token), 3, 2000, context);
    if (!res.success) {
      throw new Error(res.message);
    }
    return res.response.result.filter(tweet => tweet.status === 'live');
  } catch (error) {
    logger.error(`Failed to fetch tweets: ${error.message}`, { context });
    return [];
  }
}

async function performVote(token, tweetId, proxy, context) {
  const voteValue = true;
  const payload = { tweetId, vote: voteValue };
  const res = await requestWithRetry('post', 'https://hub.playai.network/api/mining/vote', payload, getAxiosConfig(proxy, token), 3, 2000, context);
  return { ...res, voteValue };
}

async function fetchVerifiedVotes(token, proxy, context) {
  try {
    const res = await requestWithRetry('get', 'https://hub.playai.network/api/mining/tweets/verified?page=1&limit=10', null, getAxiosConfig(proxy, token), 3, 2000, context);
    if (!res.success) {
      throw new Error(res.message);
    }
    return res.response.result;
  } catch (error) {
    logger.error(`Failed to fetch verified votes: ${error.message}`, { context });
    return [];
  }
}

async function fetchUserInfo(token, proxy, context) {
  try {
    const res = await requestWithRetry('get', `${BASE_URL}/user`, null, getAxiosConfig(proxy, token), 3, 2000, context);
    if (!res.success) {
      throw new Error(res.message);
    }
    const data = res.response;
    return {
      username: data.user.username,
      auraPoints: data.user.credit,
      address: data.wallets[0]?.address || 'N/A'
    };
  } catch (error) {
    logger.error(`Failed to fetch user info: ${error.message}`, { context });
    return { username: 'Unknown', auraPoints: 'N/A', address: 'N/A' };
  }
}

async function processAccount(pk, index, total, proxy = null) {
  const context = `Account ${index + 1}/${total}`;
  logger.info(chalk.bold.magentaBright(`Starting account processing`), { emoji: '🚀 ', context });

  printHeader(`Account Info ${context}`);
  const ip = await getPublicIP(proxy, context);
  printInfo('IP', ip, context);
  let cleanedPk = pk.trim();
  if (cleanedPk.startsWith('0x')) {
    cleanedPk = cleanedPk.slice(2);
  }
  let address = 'N/A';
  try {
    if (cleanedPk.length === 64 && /^[0-9a-fA-F]{64}$/.test(cleanedPk)) {
      const signingKey = new ethers.SigningKey('0x' + cleanedPk);
      const publicKey = signingKey.publicKey;
      address = ethers.computeAddress(publicKey);
    } else {
      logger.warn('Invalid private key format for address computation', { context });
    }
  } catch (error) {
    logger.warn(`Failed to compute address: ${error.message}`, { context });
  }
  printInfo('Address', address, context);
  console.log('\n');

  const loginRes = await loginWithWallet(pk, proxy, context);
  if (loginRes.error) {
    logger.error(`Skipping account due to login error: ${loginRes.error}`, { context });
    return;
  }
  const { jwt: token } = loginRes;

  logger.info('Starting check-in process...', { context });
  console.log('\n');
  await performCheckin(token, proxy, context);

  console.log('\n');
  logger.info('Starting missions process...', { context });
  console.log('\n');
  const missions = await fetchMissions(token, proxy, context);
  if (missions.length === 0) {
    logger.info('No missions available', { emoji: '⚠️ ', context });
  } else {
    const bar = new ProgressBar('Processing [:bar] :percent :etas', {
      complete: '█',
      incomplete: '░',
      width: 30,
      total: missions.length
    });
    let completedMissions = 0;
    let skippedMissions = 0;

    for (const mission of missions) {
      if (!mission.completed) {
        const result = await completeMission(token, mission, proxy, context);
        if (result.success) {
          mission.completed = true;
          completedMissions++;
        } else {
          skippedMissions++;
        }
      }
      bar.tick();
      await delay(2);
    }
    await formatTaskTable(missions, context);
    logger.info(`Processed ${missions.length} missions: ${completedMissions} completed, ${skippedMissions} skipped`, { emoji: '📊  ', context });
  }

  console.log('\n');
  logger.info('Starting voting process...', { context });
  console.log('\n');
  let quota = await fetchVoteQuota(token, proxy, context);
  logger.info(`Vote quota: ${quota.remaining} remaining out of ${quota.total}`, { context });

  if (quota.remaining > 0) {
    const tweets = await fetchTweets(token, proxy, context);
    if (tweets.length > 0) {
      const maxVotes = Math.min(quota.remaining, tweets.length);
      const bar = new ProgressBar('Voting [:bar] :percent :etas', {
        complete: '█',
        incomplete: '░',
        width: 30,
        total: maxVotes
      });
      let voted = 0;
      let votedTweets = [];

      for (const tweet of tweets) {
        if (voted >= quota.remaining) break;
        const spinner = ora({ text: `Voting on ${tweet.title}...`, spinner: 'dots' }).start();
        const voteRes = await performVote(token, tweet.id, proxy, context);
        if (voteRes.success) {
          const voteStatus = voteRes.voteValue ? 'Voted YES' : 'Voted NO';
          spinner.succeed(chalk.bold.greenBright(`  ${voteStatus} on: ${tweet.title}`));
          votedTweets.push({ id: tweet.id, title: tweet.title, status: voteStatus });
          voted++;
        } else {
          spinner.fail(chalk.bold.redBright(`  Failed to vote on ${tweet.title}: ${voteRes.message}`));
          votedTweets.push({ id: tweet.id, title: tweet.title, status: 'Failed' });
          if (voteRes.message && voteRes.message.includes('voted 15 times today')) {
            break;
          }
        }
        bar.tick();
        await delay(2);
      }
      logger.info(`  Voted on ${voted} tweets`, { context });
    }
  } else {
    logger.info('No remaining votes, skipping voting.', { context });
  }

  quota = await fetchVoteQuota(token, proxy, context);

  const verifiedVotes = await fetchVerifiedVotes(token, proxy, context);
  if (verifiedVotes.length > 0) {
    await formatVoteTable(verifiedVotes, context, true);
  } else {
    logger.info('No verified votes found.', { context });
  }

  printHeader(`Account Stats ${context}`);
  const userInfo = await fetchUserInfo(token, proxy, context);
  printInfo('Username', userInfo.username, context);
  printInfo('Address', userInfo.address, context);
  printInfo('Aura Points', userInfo.auraPoints, context);

  logger.info(chalk.bold.greenBright(`Completed account processing`), { emoji: '🎉 ', context });
}

async function askQuestion(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => rl.question(query, ans => {
    rl.close();
    resolve(ans);
  }));
}

let globalUseProxy = false;
let globalProxies = [];

async function initializeConfig() {
  const useProxyAns = await askQuestion(chalk.cyanBright('🔌 Do You Want Use Proxy? (y/n): '));
  if (useProxyAns.trim().toLowerCase() === 'y') {
    globalUseProxy = true;
    globalProxies = await readProxies();
    if (globalProxies.length === 0) {
      globalUseProxy = false;
      logger.warn('No proxies available, proceeding without proxy.', { emoji: '⚠️ ' });
    }
  } else {
    logger.info('Proceeding without proxy.', { emoji: 'ℹ️ ' });
  }
}

async function runCycle() {
  const pks = await readPrivateKeys();
  if (pks.length === 0) {
    logger.error('No private keys found in pk.txt. Exiting cycle.', { emoji: '❌ ' });
    return;
  }

  for (let i = 0; i < pks.length; i++) {
    const proxy = globalUseProxy ? globalProxies[i % globalProxies.length] : null;
    try {
      await processAccount(pks[i], i, pks.length, proxy);
    } catch (error) {
      logger.error(`Error processing account: ${error.message}`, { emoji: '❌ ', context: `Account ${i + 1}/${pks.length}` });
    }
    if (i < pks.length - 1) {
      console.log('\n\n');
    }
    await delay(5);
  }
}

async function run() {
  const terminalWidth = process.stdout.columns || 80;
  cfonts.say('NT EXHAUST', {
    font: 'block',
    align: 'center',
    colors: ['cyan', 'magenta'],
    background: 'transparent',
    letterSpacing: 1,
    lineHeight: 1,
    space: true
  });
  console.log(gradient.retro(centerText('=== Telegram Channel 🚀 : NT EXHAUST @NTExhaust ===', terminalWidth)));
  console.log(gradient.retro(centerText('✪ PLAYHUB AI AUTO DAILY BOT ✪', terminalWidth)));
  console.log('\n');
  await initializeConfig();

  while (true) {
    await runCycle();
    logger.info(chalk.bold.yellowBright('Cycle completed. Waiting 24 hours...'), { emoji: '🔄 ' });
    await delay(86400);
  }
}

run().catch(error => logger.error(`Fatal error: ${error.message}`, { emoji: '❌' }));