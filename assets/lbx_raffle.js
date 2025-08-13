// L3Z Raffle (ES5) — save as: assets/js/l3z_raffle.es5.js
(function (global) {
  'use strict';

  var L3Z_Raffle = {
    keyBank: function(user){ return 'raffle:bank:' + user; },
    keyTickets: function(user){ return 'raffle:tickets:' + user; },
    keyBackfilled: function(user){ return 'raffle:backfilled:v1:' + user; },
    keyWallet: function(user){ return 'sb:wallet:' + user; },
    keyTx: function(user){ return 'sb:tx:' + user; },

    _read: function(key, fallbackJson){
      try {
        var raw = localStorage.getItem(key);
        if (raw === null || raw === undefined) raw = fallbackJson;
        return JSON.parse(raw);
      } catch (_e) {
        try { return JSON.parse(fallbackJson); } catch (_e2) { return null; }
      }
    },
    _write: function(key, val){ localStorage.setItem(key, JSON.stringify(val)); },

    getBank: function(user){
      var v = this._read(this.keyBank(user), '0');
      return Number(v || 0);
    },
    setBank: function(user, v){ this._write(this.keyBank(user), Number(v || 0)); },

    getTickets: function(user){
      var arr = this._read(this.keyTickets(user), '[]');
      return Array.isArray(arr) ? arr : [];
    },
    setTickets: function(user, arr){
      this._write(this.keyTickets(user), Array.isArray(arr) ? arr : []);
    },

    totalTickets: function(user){ return this.getTickets(user).length; },

    genCode: function(){
      var d = new Date();
      function pad(n){ n = String(n); return n.length < 2 ? '0'+n : n; }
      var date = d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate());

      var rnd = '';
      try {
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
          var a = new Uint32Array(2);
          crypto.getRandomValues(a);
          rnd = (a[0].toString(36) + a[1].toString(36)).toUpperCase();
        } else {
          rnd = Math.random().toString(36).slice(2, 10).toUpperCase();
        }
      } catch (_e) {
        rnd = Math.random().toString(36).slice(2, 10).toUpperCase();
      }
      return 'RF-' + date + '-' + rnd.slice(0,6);
    },

    // +10 LBX (any source except 'lucky7') => 1 ticket
    award: function(user, lbxAdded, source){
      var add = Number(lbxAdded || 0);
      if (add <= 0) return { minted: 0, bank: this.getBank(user) };
      source = String(source || '').toLowerCase();
      if (source === 'lucky7') return { minted: 0, bank: this.getBank(user) };

      var bank = this.getBank(user) + add;
      var minted = 0;
      var tix = this.getTickets(user);

      while (bank >= 10) {
        bank -= 10;
        minted += 1;
        tix.push({
          code: this.genCode(),
          ts: Date.now(),
          source: source || 'general',
          lbx: 10
        });
      }
      this.setBank(user, bank);
      this.setTickets(user, tix);
      return { minted: minted, bank: bank };
    },

    // optional one-time backfill from TX history (credits only, excluding Lucky 7)
    backfillFromTx: function(user){
      var flagKey = this.keyBackfilled(user);
      if (localStorage.getItem(flagKey)) return { minted: 0, skipped: true };

      var tx = this._read(this.keyTx(user), '[]');
      if (!Array.isArray(tx)) tx = [];

      var totalCred = 0;
      for (var i=0;i<tx.length;i++){
        var t = tx[i] || {};
        var amt = Number(t.amount || 0);
        var note = String(t.note || '');
        if (amt > 0 && !/lucky ?7/i.test(note)) totalCred += amt;
      }

      var minted = 0;
      var remaining = totalCred;
      var tix = this.getTickets(user);
      while (remaining >= 10) {
        remaining -= 10;
        minted += 1;
        tix.push({ code: this.genCode(), ts: Date.now(), source: 'backfill', lbx: 10 });
      }
      this.setTickets(user, tix);
      this.setBank(user, remaining);
      localStorage.setItem(flagKey, '1');
      return { minted: minted, bank: remaining, skipped: false };
    }
  };

  // expose API
  global.L3Z_Raffle = L3Z_Raffle;

  // convenience wrapper: credit wallet + ledger + tickets
  global.creditLBX = function(user, amount, note, source){
    user = String(user || 'guest');
    amount = Number(amount || 0);
    note = note || '';

    var WKEY = 'sb:wallet:' + user;
    var wallet;
    try { wallet = JSON.parse(localStorage.getItem(WKEY) || '{"balance":0}'); }
    catch (_e) { wallet = { balance: 0 }; }
    wallet.balance = Number(wallet.balance || 0) + amount;
    localStorage.setItem(WKEY, JSON.stringify(wallet));

    var TKEY = 'sb:tx:' + user;
    var tx;
    try { tx = JSON.parse(localStorage.getItem(TKEY) || '[]'); }
    catch (_e2) { tx = []; }
    var id;
    try {
      id = (typeof crypto !== 'undefined' && crypto.randomUUID)
        ? crypto.randomUUID()
        : ('b_' + Math.random().toString(36).slice(2));
    } catch (_e3) {
      id = 'b_' + Math.random().toString(36).slice(2);
    }
    tx.unshift({
      id: id,
      ts: Date.now(),
      type: 'credit',
      amount: amount,
      note: note
    });
    localStorage.setItem(TKEY, JSON.stringify(tx));

    L3Z_Raffle.award(user, amount, source || '');
  };

})(window);
