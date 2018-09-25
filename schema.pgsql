--
-- PostgreSQL database dump
--

-- Dumped from database version 10.5 (Ubuntu 10.5-0ubuntu0.18.04)
-- Dumped by pg_dump version 10.5 (Ubuntu 10.5-0ubuntu0.18.04)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: macalias; Type: TABLE; Schema: public; Owner: wifitrack
--

CREATE TABLE public.macalias (
    mac macaddr NOT NULL,
    alias character varying,
    notes character varying
);


ALTER TABLE public.macalias OWNER TO wifitrack;

--
-- Name: seenclients; Type: TABLE; Schema: public; Owner: wifitrack
--

CREATE TABLE public.seenclients (
    id integer NOT NULL,
    mac macaddr,
    netname character varying,
    rssi integer,
    rxphy integer,
    age integer,
    "time" timestamp without time zone DEFAULT now(),
    lastseen timestamp without time zone,
    scanner character varying
);


ALTER TABLE public.seenclients OWNER TO wifitrack;

--
-- Name: seenclients_id_seq; Type: SEQUENCE; Schema: public; Owner: wifitrack
--

ALTER TABLE public.seenclients ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.seenclients_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: vendor; Type: TABLE; Schema: public; Owner: wifitrack
--

CREATE TABLE public.vendor (
    mac character varying,
    shortname character varying,
    longname character varying
);


ALTER TABLE public.vendor OWNER TO wifitrack;

--
-- Name: macalias macalias_pkey; Type: CONSTRAINT; Schema: public; Owner: wifitrack
--

ALTER TABLE ONLY public.macalias
    ADD CONSTRAINT macalias_pkey PRIMARY KEY (mac);


--
-- Name: seenclients seenclients_pkey; Type: CONSTRAINT; Schema: public; Owner: wifitrack
--

ALTER TABLE ONLY public.seenclients
    ADD CONSTRAINT seenclients_pkey PRIMARY KEY (id);


--
-- Name: mac_time; Type: INDEX; Schema: public; Owner: wifitrack
--

CREATE INDEX mac_time ON public.seenclients USING btree (mac, "time" DESC);


--
-- Name: seenclients_lastseen_idx; Type: INDEX; Schema: public; Owner: wifitrack
--

CREATE INDEX seenclients_lastseen_idx ON public.seenclients USING btree (lastseen DESC);


--
-- PostgreSQL database dump complete
--

